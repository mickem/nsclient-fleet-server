//! Host facts: the agent's inventory of the machine it runs on.
//!
//! The document is up to a megabyte and changes rarely, so it only travels when the server
//! does not already have it:
//!
//! * Every desired-state poll (`?facts_hash=`) and state report (`"facts_hash"`) carries the
//!   hash of the agent's current document.
//! * Every answer to those carries the hash *we* hold in `X-Facts-Hash` ([`advertise`]),
//!   `none` when we hold nothing. It is a header so that it rides on the 304 a host in sync
//!   gets on nearly every poll.
//! * The agent uploads to `POST /agent/v1/facts` ([`upload`]) only when the two differ.
//!
//! So a steady-state host costs one indexed read per poll and nothing more: no document, no
//! write. Sending the header at all is what tells an agent this server does facts — one
//! that never sees it never uploads.
//!
//! See [`fleet_core::facts`] for the wire format and the document diff.

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::facts::{
    self, FactChange, AGENT_SOURCE, EMPTY_FACTS_HASH, FACTS_HASH_HEADER, FACTS_HASH_NONE,
};
use fleet_storage::{FactsHashes, HostFactsRepo, HostRepo, ReplaceOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::auth::AuthedUser;
use crate::mtls::PeerHostContext;
use crate::AppState;

/// Largest upload body accepted. The agent caps its own document at `[/settings/facts] max
/// size`, a megabyte by default; this leaves room for an operator who raised that, while a
/// larger body is refused with 413 — which the agent reports once, naming the sets to turn
/// off, and does not retry until the document changes.
pub const MAX_FACTS_BODY_BYTES: usize = 4 * 1024 * 1024;

/// History entries kept per host.
const KEEP_HISTORY: i64 = 100;

/// Changes listed per history entry. The rest are counted: a host that installed a few
/// hundred packages in one go is one entry saying so, not a history row the size of the
/// document.
const MAX_CHANGES_PER_ENTRY: usize = 200;

/// History entries returned with a host's facts.
const CHANGES_SHOWN: i64 = 50;

/// Attempts at storing a document when another write keeps replacing it underneath.
const STORE_ATTEMPTS: usize = 3;

fn header_name() -> HeaderName {
    HeaderName::from_static(FACTS_HASH_HEADER)
}

/// The `X-Facts-Hash` value for this host, recording the hash the agent reported on the way.
///
/// `None` — send no header — when the host cannot be read. No header means "this server does
/// not do facts" to the agent, which then simply does not upload: the safe answer to a
/// failure, where claiming `none` would invite a megabyte on every poll.
pub async fn advertise(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
    reported: Option<&str>,
) -> Option<HeaderValue> {
    let repo = HostFactsRepo::new(&state.db);
    let hashes = match repo.hashes(tenant_id, host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(error = %e, "facts hash lookup failed");
            return None;
        }
    };
    let mut held = hashes.held;
    // Written only when it moved, so a steady-state poll stays a read. A malformed value is
    // ignored rather than refused: it is descriptive, and failing a poll over it would cost
    // the host its configuration.
    if let Some(reported) = reported.and_then(facts::normalize_hash) {
        if hashes.reported.as_deref() != Some(reported.as_str()) {
            if let Err(e) = repo.set_reported_hash(tenant_id, host_id, &reported).await {
                tracing::error!(error = %e, "set_reported_hash failed");
            }
        }
        // The operator switched every fact set off. The hash alone says what the document
        // is — `{}` — so there is nothing to wait for: clear what we hold now, rather than
        // keep showing the last inventory as merely "outdated" until an upload of an empty
        // document that the agent has no reason to send.
        if reported == EMPTY_FACTS_HASH && held.as_deref().is_some_and(|h| h != EMPTY_FACTS_HASH) {
            match store(state, tenant_id, host_id, EMPTY_FACTS_HASH, "{}", None).await {
                Ok(_) => {
                    tracing::info!(%host_id, "host has no fact set enabled any more; cleared its inventory");
                    held = Some(EMPTY_FACTS_HASH.to_owned());
                }
                Err(e) => tracing::error!(error = %e, "clearing host facts failed"),
            }
        }
    }
    HeaderValue::from_str(held.as_deref().unwrap_or(FACTS_HASH_NONE)).ok()
}

/// Attach the header to a response, if there is one to attach.
pub fn with_header(mut response: Response, value: Option<HeaderValue>) -> Response {
    if let Some(v) = value {
        response.headers_mut().insert(header_name(), v);
    }
    response
}

/// `POST /agent/v1/facts`: store the host's document.
///
/// The body is read as bytes, not through `Json`, because the hash covers the `facts` value
/// exactly as sent and is verified — and stored — against those bytes.
pub async fn upload(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    body: Bytes,
) -> Response {
    let upload = match facts::parse_upload(&body) {
        Ok(u) => u,
        Err(e) => {
            tracing::info!(host_id = %ctx.host_id, error = %e, "rejected a facts upload");
            return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
        }
    };
    let repo = HostFactsRepo::new(&state.db);
    // A retried upload of what we already hold is the common repeat: answer it from the
    // hash alone, without walking the document or reading the stored one.
    let already_held = match repo.hashes(ctx.tenant_id, &ctx.host_id).await {
        Ok(h) => h.and_then(|h| h.held).as_deref() == Some(upload.facts_hash.as_str()),
        Err(e) => {
            tracing::error!(error = %e, "facts hash lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if !already_held {
        match store(
            &state,
            ctx.tenant_id,
            &ctx.host_id,
            &upload.facts_hash,
            upload.facts,
            upload.collected_at.as_deref(),
        )
        .await
        {
            Ok(ReplaceOutcome::Stored) => tracing::info!(
                host_id = %ctx.host_id,
                facts_hash = %upload.facts_hash,
                size_bytes = upload.facts.len(),
                "stored host facts"
            ),
            Ok(ReplaceOutcome::Unchanged) => { /* a concurrent upload of the same document */ }
            Ok(ReplaceOutcome::Conflict) => {
                // The agent retries on its next poll; a 503 is "try again", not a refusal.
                tracing::warn!(host_id = %ctx.host_id, "facts upload kept racing another write");
                return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
            }
            Ok(ReplaceOutcome::NoHost) => {
                return (StatusCode::NOT_FOUND, "host not found").into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "storing host facts failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }
    // The agent obviously holds what it just sent.
    if let Err(e) = repo
        .set_reported_hash(ctx.tenant_id, &ctx.host_id, &upload.facts_hash)
        .await
    {
        tracing::error!(error = %e, "set_reported_hash failed");
    }

    let held = HeaderValue::from_str(&upload.facts_hash).ok();
    with_header(Json(serde_json::json!({})).into_response(), held)
}

/// Store `json` as the agent's document, and what changed since the previous one.
///
/// The previous document is read and diffed here, outside any transaction, and the write is
/// a compare-and-set against its hash, so the single write connection is never held while a
/// megabyte document is parsed. The new document is parsed at most once, and only when it
/// actually differs from what is stored.
async fn store(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
    hash: &str,
    json: &str,
    collected_at: Option<&str>,
) -> anyhow::Result<ReplaceOutcome> {
    let repo = HostFactsRepo::new(&state.db);
    let mut document: Option<Value> = None;
    for _ in 0..STORE_ATTEMPTS {
        let previous = repo.get(tenant_id, host_id, AGENT_SOURCE).await?;
        let previous_hash = previous.as_ref().map(|p| p.facts_hash.as_str());
        if previous_hash == Some(hash) {
            return Ok(ReplaceOutcome::Unchanged);
        }
        if document.is_none() {
            document = Some(serde_json::from_str(json)?);
        }
        let entry = history_entry(
            previous.as_ref().map(|p| p.facts_json.as_str()),
            document.as_ref().expect("parsed above"),
        );
        let outcome = repo
            .replace(
                tenant_id,
                host_id,
                AGENT_SOURCE,
                hash,
                json,
                collected_at,
                previous_hash,
                entry.as_deref(),
                KEEP_HISTORY,
            )
            .await?;
        if outcome != ReplaceOutcome::Conflict {
            return Ok(outcome);
        }
    }
    Ok(ReplaceOutcome::Conflict)
}

#[derive(Serialize, Deserialize)]
struct HistoryEntry {
    /// The first document this host sent: nothing to compare it with.
    initial: bool,
    changes: Vec<FactChange>,
    truncated: usize,
}

/// What to record about replacing `previous` with `document`, if anything.
fn history_entry(previous: Option<&str>, document: &Value) -> Option<String> {
    let empty = || Value::Object(Default::default());
    let entry = match previous {
        // A first document with nothing in it is a host that has nothing enabled, not an
        // event worth a line.
        None if document.as_object().is_some_and(|o| o.is_empty()) => return None,
        None => HistoryEntry {
            initial: true,
            changes: Vec::new(),
            truncated: 0,
        },
        Some(previous) => {
            // A stored document that no longer parses is compared as empty, so the new one
            // reads as all-new rather than blocking the upload.
            let old = serde_json::from_str(previous).unwrap_or_else(|_| empty());
            let d = facts::diff(&old, document, MAX_CHANGES_PER_ENTRY);
            if d.is_empty() {
                return None;
            }
            HistoryEntry {
                initial: false,
                changes: d.changes,
                truncated: d.truncated,
            }
        }
    };
    serde_json::to_string(&entry).ok()
}

/// How the host's stored inventory relates to what the agent holds.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactsStatus {
    /// The agent never sent a hash: it predates facts, or has not polled since.
    NotReported,
    /// The agent has no fact set enabled.
    NothingEnabled,
    /// We hold what the agent holds.
    Current,
    /// The agent has a document and we have none yet; the upload follows its next poll.
    Pending,
    /// The agent has a newer document than the one shown; same.
    Outdated,
}

pub fn status(h: &FactsHashes) -> FactsStatus {
    match (h.held.as_deref(), h.reported.as_deref()) {
        (_, Some(EMPTY_FACTS_HASH))
            if matches!(h.held.as_deref(), None | Some(EMPTY_FACTS_HASH)) =>
        {
            FactsStatus::NothingEnabled
        }
        (None, None) => FactsStatus::NotReported,
        (Some(_), None) => FactsStatus::Current,
        (Some(held), Some(reported)) if held == reported => FactsStatus::Current,
        (None, Some(_)) => FactsStatus::Pending,
        (Some(_), Some(_)) => FactsStatus::Outdated,
    }
}

#[derive(Serialize)]
pub struct FactsChangesView {
    pub source: String,
    pub at: i64,
    pub facts_hash: String,
    pub initial: bool,
    pub changes: Vec<FactChange>,
    pub truncated: usize,
}

#[derive(Serialize)]
pub struct HostFactsView {
    /// Which source this is. Only `agent` today; imported sources will sit beside it.
    pub source: &'static str,
    pub status: FactsStatus,
    /// The stored document, or null when the host never uploaded one.
    pub facts: Option<Value>,
    pub facts_hash: Option<String>,
    /// What the agent last said it holds.
    pub reported_hash: Option<String>,
    /// When the agent collected it, by its own clock (ISO 8601).
    pub collected_at: Option<String>,
    /// When we received it.
    pub received_at: Option<i64>,
    pub size_bytes: Option<i64>,
    /// Newest first.
    pub changes: Vec<FactsChangesView>,
}

/// `GET /api/hosts/:id/facts`: the host's inventory as its agent reported it, its
/// freshness, and its recent history.
pub async fn host_facts(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
) -> Response {
    match HostRepo::new(&state.db).get(who.tenant_id, &host_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    }
    let repo = HostFactsRepo::new(&state.db);
    let loaded = async {
        let hashes = repo
            .hashes(who.tenant_id, &host_id)
            .await?
            .unwrap_or_default();
        let stored = repo.get(who.tenant_id, &host_id, AGENT_SOURCE).await?;
        let changes = repo
            .list_changes(who.tenant_id, &host_id, AGENT_SOURCE, CHANGES_SHOWN)
            .await?;
        anyhow::Ok((hashes, stored, changes))
    }
    .await;
    let (hashes, stored, changes) = match loaded {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "host facts load failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let changes = changes
        .into_iter()
        .filter_map(|row| {
            let entry: HistoryEntry = serde_json::from_str(&row.changes_json).ok()?;
            Some(FactsChangesView {
                source: row.source,
                at: row.at,
                facts_hash: row.facts_hash,
                initial: entry.initial,
                changes: entry.changes,
                truncated: entry.truncated,
            })
        })
        .collect();

    let stored = stored.as_ref();
    let view = HostFactsView {
        source: AGENT_SOURCE,
        status: status(&hashes),
        facts: stored.and_then(|s| serde_json::from_str(&s.facts_json).ok()),
        facts_hash: stored.map(|s| s.facts_hash.clone()),
        reported_hash: hashes.reported,
        collected_at: stored.and_then(|s| s.collected_at.clone()),
        received_at: stored.map(|s| s.received_at),
        size_bytes: stored.map(|s| s.size_bytes),
        changes,
    };
    Json(view).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(held: Option<&str>, reported: Option<&str>) -> FactsHashes {
        FactsHashes {
            held: held.map(str::to_owned),
            reported: reported.map(str::to_owned),
        }
    }

    #[test]
    fn status_reads_both_hashes() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        assert_eq!(status(&h(None, None)), FactsStatus::NotReported);
        assert_eq!(
            status(&h(None, Some(EMPTY_FACTS_HASH))),
            FactsStatus::NothingEnabled
        );
        assert_eq!(
            status(&h(Some(EMPTY_FACTS_HASH), Some(EMPTY_FACTS_HASH))),
            FactsStatus::NothingEnabled
        );
        // Only until the next poll or report: `advertise` clears a stored inventory as soon
        // as the agent reports the empty document's hash.
        assert_eq!(
            status(&h(Some(&a), Some(EMPTY_FACTS_HASH))),
            FactsStatus::Outdated
        );
        assert_eq!(status(&h(None, Some(&a))), FactsStatus::Pending);
        assert_eq!(status(&h(Some(&a), Some(&a))), FactsStatus::Current);
        assert_eq!(status(&h(Some(&a), Some(&b))), FactsStatus::Outdated);
        assert_eq!(status(&h(Some(&a), None)), FactsStatus::Current);
    }

    #[test]
    fn an_empty_first_document_is_not_history() {
        assert!(history_entry(None, &serde_json::json!({})).is_none());
        let first = history_entry(None, &serde_json::json!({"os": {}})).unwrap();
        let e: HistoryEntry = serde_json::from_str(&first).unwrap();
        assert!(e.initial);
    }

    #[test]
    fn an_unchanged_document_is_not_history() {
        let doc = serde_json::json!({"os": {"family": "linux"}});
        assert!(history_entry(Some(r#"{"os":{"family":"linux"}}"#), &doc).is_none());
        let e: HistoryEntry = serde_json::from_str(
            &history_entry(Some(r#"{"os":{"family":"windows"}}"#), &doc).unwrap(),
        )
        .unwrap();
        assert!(!e.initial);
        assert_eq!(e.changes.len(), 1);
        assert_eq!(e.changes[0].path, "os.family");
    }
}
