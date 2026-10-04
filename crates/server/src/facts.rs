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
    body::{Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::facts::{
    self, FactsDiff, AGENT_SOURCE, EMPTY_FACTS_HASH, FACTS_HASH_HEADER, FACTS_HASH_NONE,
};
use fleet_core::selector::{scalar_text, FactPath, HostFacts, MAX_VALUE_LEN};
use fleet_core::time::now_unix;
use fleet_storage::{FactsHashes, HostFactsRepo, HostRepo, NewFacts, ReplaceOutcome};
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

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

/// How long an agent must keep reporting the empty document before the inventory it had is
/// cleared. One empty report — an agent that polled before its collectors ran — would
/// otherwise wipe the inventory and restore it on the next poll, writing a "removed" and an
/// "added" history row every time, and handing a misbehaving agent a cheap way to make the
/// server diff its whole document twice per cycle.
pub const EMPTY_CLEAR_GRACE_SECS: i64 = 600;

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
    // No (usable) hash: an agent without facts, or a build that cannot hash. It uploads
    // nothing whatever the answer, and only the header's presence means anything to it, so
    // the lookup is spared. A malformed value is ignored rather
    // than refused: it is descriptive, and failing a poll over it would cost the host its
    // configuration.
    let Some(reported) = reported.and_then(facts::normalize_hash) else {
        // It no longer vouches for what we hold (a downgraded agent, facts switched off in
        // it), so forget what it last said: the page then reads "not reported" instead of
        // "up to date" forever. Checked on the read pool first, so a fleet of agents that
        // never sent a hash costs one read per poll and never queues on the single write
        // connection; the write happens once, when an agent stops sending one.
        let repo = HostFactsRepo::new(&state.db);
        match repo.hashes(tenant_id, host_id).await {
            Ok(Some(h)) if h.reported.is_some() => {
                if let Err(e) = repo.clear_reported_hash(tenant_id, host_id).await {
                    tracing::error!(error = %e, "clear_reported_hash failed");
                }
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "facts hash lookup failed"),
        }
        return Some(HeaderValue::from_static(FACTS_HASH_NONE));
    };
    let repo = HostFactsRepo::new(&state.db);
    let hashes = match repo.hashes(tenant_id, host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return None,
        Err(e) => {
            tracing::error!(error = %e, "facts hash lookup failed");
            return None;
        }
    };
    let mut advertised = hashes.held.clone();
    // Written only when it moved, so a steady-state poll stays a read.
    if hashes.reported.as_deref() != Some(reported.as_str()) {
        if let Err(e) = repo.set_reported_hash(tenant_id, host_id, &reported).await {
            tracing::error!(error = %e, "set_reported_hash failed");
        }
    }
    match empty_over_inventory(&hashes, &reported, now_unix()) {
        EmptyOverInventory::NotApplicable => {}
        EmptyOverInventory::Due => {
            // The operator switched every fact set off, and the agent has said so for
            // the whole grace period. The hash alone says what the document is — `{}` —
            // so clear what we hold rather than wait for an upload of it.
            match store(
                state,
                tenant_id,
                host_id,
                AGENT_SOURCE,
                EMPTY_FACTS_HASH,
                Arc::from("{}"),
                None,
            )
            .await
            {
                Ok(ReplaceOutcome::Stored) => {
                    tracing::info!(%host_id, "host has no fact set enabled any more; cleared its inventory");
                    advertised = Some(EMPTY_FACTS_HASH.to_owned());
                }
                // Another request cleared it first: nothing done here, nothing to log.
                Ok(ReplaceOutcome::Unchanged) => advertised = Some(EMPTY_FACTS_HASH.to_owned()),
                // Not cleared: keep answering with what we do hold, and try again on
                // the next poll.
                Ok(outcome) => {
                    tracing::warn!(%host_id, ?outcome, "clearing host facts did not take")
                }
                Err(e) => tracing::error!(error = %e, "clearing host facts failed"),
            }
        }
        EmptyOverInventory::Pending => {
            // Answer as if the clear had happened, so the agent does not upload `{}` in
            // the meantime; if it goes back to its old document before the grace period
            // is up, the answer is the held hash again and nothing moved.
            advertised = Some(EMPTY_FACTS_HASH.to_owned());
        }
    }
    HeaderValue::from_str(advertised.as_deref().unwrap_or(FACTS_HASH_NONE)).ok()
}

/// What to do with the agent holding `hash` when it is the empty document and we hold a
/// real inventory. The one place the grace rule lives: the poll and the upload both ask it.
#[derive(Debug, PartialEq, Eq)]
enum EmptyOverInventory {
    /// Not that case: `hash` is a real document, or there is nothing to clear.
    NotApplicable,
    /// The agent has not said so for the whole grace period yet: keep the inventory.
    Pending,
    /// It has: clear the inventory.
    Due,
}

fn empty_over_inventory(h: &FactsHashes, hash: &str, now: i64) -> EmptyOverInventory {
    if hash != EMPTY_FACTS_HASH || !holds_inventory(h) {
        EmptyOverInventory::NotApplicable
    } else if empty_for_long_enough(h, now) {
        EmptyOverInventory::Due
    } else {
        EmptyOverInventory::Pending
    }
}

/// Whether we hold an inventory with something in it.
fn holds_inventory(h: &FactsHashes) -> bool {
    h.held
        .as_deref()
        .is_some_and(|held| held != EMPTY_FACTS_HASH)
}

/// Whether the agent has reported the empty document for the whole grace period. `hashes`
/// is what was stored *before* this request, so a report that only now turned empty has
/// not.
fn empty_for_long_enough(h: &FactsHashes, now: i64) -> bool {
    h.reported.as_deref() == Some(EMPTY_FACTS_HASH)
        && h.reported_since
            .is_some_and(|since| now - since >= EMPTY_CLEAR_GRACE_SECS)
}

/// A verified upload, owned so it can come back from a blocking task.
struct Upload {
    facts_hash: String,
    collected_at: Option<String>,
    facts: Arc<str>,
}

enum BodyError {
    /// Over the limit. `drained`: the rest was read and discarded, so the refusal reaches
    /// the client; otherwise the connection has to be closed after it.
    TooLarge {
        drained: bool,
    },
    Unreadable,
}

/// How much of an oversized body is read and discarded so that the client, still writing
/// it, sees the 413 rather than a connection reset — which it would take for a network
/// error, and resend the document on every poll. Past this, the connection is closed.
const MAX_DRAINED_BYTES: usize = 4 * MAX_FACTS_BODY_BYTES;

/// The whole body, if it is no larger than `limit`. A larger one is drained (up to
/// [`MAX_DRAINED_BYTES`]) without being kept; a `Content-Length` that already says it is
/// too large skips the buffering, and one past the drain limit skips the reading.
async fn read_capped(headers: &HeaderMap, body: Body, limit: usize) -> Result<Bytes, BodyError> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_DRAINED_BYTES) {
        return Err(BodyError::TooLarge { drained: false });
    }
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    let mut seen = declared.filter(|&n| n > limit).map_or(0, |_| limit + 1);
    let mut keep = seen == 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BodyError::Unreadable)?;
        seen += chunk.len();
        if seen > MAX_DRAINED_BYTES {
            return Err(BodyError::TooLarge { drained: false });
        }
        if keep && seen > limit {
            keep = false;
            buf = Vec::new();
        }
        if keep {
            buf.extend_from_slice(&chunk);
        }
    }
    if keep {
        Ok(Bytes::from(buf))
    } else {
        Err(BodyError::TooLarge { drained: true })
    }
}

/// Refuse an upload, and record that it was: the agent does not retry a refused document,
/// so without the record the host would read as "inventory on its way" until its inventory
/// next changes.
///
/// `hash`: the refused document's own, when the body said it; otherwise the refusal is
/// recorded against the hash the agent last reported, which is the document it was sending.
async fn refuse(
    repo: &HostFactsRepo<'_>,
    ctx: &PeerHostContext,
    status: StatusCode,
    hash: Option<&str>,
    message: &str,
) -> Response {
    if let Err(e) = repo
        .record_refusal(ctx.tenant_id, &ctx.host_id, status.as_u16(), hash)
        .await
    {
        tracing::error!(error = %e, "recording a facts refusal failed");
    }
    (status, message.to_owned()).into_response()
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
/// exactly as sent and is verified — and stored — against those bytes. It is read here
/// rather than through a body-limit layer so that an oversized one reaches this handler and
/// its refusal is recorded like any other.
pub async fn upload(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let repo = HostFactsRepo::new(&state.db);
    let body = match read_capped(&headers, body, MAX_FACTS_BODY_BYTES).await {
        Ok(b) => b,
        Err(BodyError::TooLarge { drained }) => {
            tracing::info!(host_id = %ctx.host_id, "refused an oversized facts upload");
            let mut response = refuse(
                &repo,
                &ctx,
                StatusCode::PAYLOAD_TOO_LARGE,
                None,
                "facts upload too large",
            )
            .await;
            if !drained {
                // Unread body left on the connection: it cannot carry another request.
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
            }
            return response;
        }
        // The connection failed mid-body: nothing was refused. 503 is the status the agent
        // retries on its next poll; a 400 would tell it never to send this document again.
        Err(BodyError::Unreadable) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "body could not be read").into_response()
        }
    };
    // Hashing and parsing up to 4 MiB is CPU work: off the async workers.
    let parsed = tokio::task::spawn_blocking(move || {
        facts::parse_upload(&body).map(|u| Upload {
            facts_hash: u.facts_hash,
            collected_at: u.collected_at,
            facts: Arc::from(u.facts),
        })
    })
    .await;
    let upload = match parsed {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            tracing::info!(host_id = %ctx.host_id, error = %e, "rejected a facts upload");
            return refuse(
                &repo,
                &ctx,
                StatusCode::BAD_REQUEST,
                e.declared_hash(),
                &e.to_string(),
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "facts upload parse task failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let hashes = match repo.hashes(ctx.tenant_id, &ctx.host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "facts hash lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if hashes.held.as_deref() == Some(upload.facts_hash.as_str()) {
        // A re-send of what we already hold: answered from the hash alone, without walking
        // the document. Only its collection time can have moved.
        if let Some(collected_at) = upload.collected_at.as_deref() {
            if let Err(e) = repo
                .refresh_collected_at(
                    ctx.tenant_id,
                    &ctx.host_id,
                    AGENT_SOURCE,
                    &upload.facts_hash,
                    collected_at,
                )
                .await
            {
                tracing::error!(error = %e, "refreshing collected_at failed");
            }
        }
    } else if empty_over_inventory(&hashes, &upload.facts_hash, now_unix())
        == EmptyOverInventory::Pending
    {
        // An empty document over a real one waits out the same grace period as an empty
        // report does; the poll that ends it clears the inventory. Accepted, so the agent
        // does not retry it.
    } else {
        match store(
            &state,
            ctx.tenant_id,
            &ctx.host_id,
            AGENT_SOURCE,
            &upload.facts_hash,
            upload.facts.clone(),
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

/// Store `json` as `source`'s document for a host, and what changed since the previous one.
///
/// The one write path for facts, whatever the source: it also drops the host's cached
/// desired state, because group selectors can read facts and a new document can move the
/// host in or out of a group. A writer that went around this would leave hosts in the wrong
/// groups until something else invalidated them.
///
/// The previous document is read and diffed here, outside any transaction, and the write is
/// a compare-and-set against its hash, so the single write connection is never held while a
/// megabyte document is parsed. The new document is parsed at most once, and only when it
/// actually differs from what is stored.
pub async fn store(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
    source: &str,
    hash: &str,
    json: Arc<str>,
    collected_at: Option<&str>,
) -> anyhow::Result<ReplaceOutcome> {
    let repo = HostFactsRepo::new(&state.db);
    let mut document: Option<Value> = None;
    for _ in 0..STORE_ATTEMPTS {
        // Callers have already compared the cheap hash (the upload and the clear both have
        // it from `hashes`), so this read is the one a diff needs. Its own hash is what the
        // write is checked against: if it moved meanwhile, the write says so and this goes
        // round again.
        let previous = repo.get(tenant_id, host_id, source).await?;
        let (previous_hash, previous_json) = previous.map(|p| (p.facts_hash, p.facts_json)).unzip();
        if previous_hash.as_deref() == Some(hash) {
            return Ok(ReplaceOutcome::Unchanged);
        }
        // Parsing and diffing two documents of up to megabytes is CPU work: off the async
        // workers. The parsed document comes back for the next attempt, if there is one.
        let (parsed, entry) = {
            let json = json.clone();
            let parsed = document.take();
            tokio::task::spawn_blocking(move || -> anyhow::Result<_> {
                let parsed = match parsed {
                    Some(d) => d,
                    None => serde_json::from_str(&json)?,
                };
                let entry = history_entry(previous_json.as_deref(), &parsed);
                Ok((parsed, entry))
            })
            .await??
        };
        document = Some(parsed);
        let doc = NewFacts {
            source,
            facts_hash: hash,
            facts_json: &json,
            collected_at,
            expected_previous: previous_hash.as_deref(),
            history: entry.as_deref(),
        };
        let outcome = repo.replace(tenant_id, host_id, &doc, KEEP_HISTORY).await?;
        if outcome == ReplaceOutcome::Stored {
            // This host's cached state only — the same scope as a change to its reported
            // tags, and for the same reason: nobody else's membership moved.
            state
                .desired_state_cache
                .invalidate_host(tenant_id, host_id);
            state
                .facts_catalog_cache
                .bump(tenant_id, CatalogChange::Stored);
        }
        if outcome != ReplaceOutcome::Conflict {
            return Ok(outcome);
        }
    }
    Ok(ReplaceOutcome::Conflict)
}

/// Delete `source`'s document for a host, and its history. Returns true iff there was one.
///
/// The counterpart of [`store`], with the same side effects: the host's cached desired
/// state goes (a group selector may have read the document), and the catalog is rebuilt.
/// `bump_catalog`: false for a caller that removes many and bumps once itself.
pub async fn remove(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
    source: &str,
    bump_catalog: bool,
) -> anyhow::Result<bool> {
    let removed = HostFactsRepo::new(&state.db)
        .delete(tenant_id, host_id, source)
        .await?;
    if removed {
        state
            .desired_state_cache
            .invalidate_host(tenant_id, host_id);
        if bump_catalog {
            state
                .facts_catalog_cache
                .bump(tenant_id, CatalogChange::Operator);
        }
    }
    Ok(removed)
}

/// Delete every document of `source` in a tenant, with [`remove`]'s side effects for each
/// host that had one. Returns how many were deleted.
pub async fn remove_source(
    state: &AppState,
    tenant_id: i64,
    source: &str,
) -> anyhow::Result<usize> {
    let hosts = HostFactsRepo::new(&state.db)
        .delete_source(tenant_id, source)
        .await?;
    for host_id in &hosts {
        state
            .desired_state_cache
            .invalidate_host(tenant_id, host_id);
    }
    if !hosts.is_empty() {
        state
            .facts_catalog_cache
            .bump(tenant_id, CatalogChange::Operator);
    }
    Ok(hosts.len())
}

/// A host's documents from `sources`, parsed, for selector evaluation.
///
/// Only the sources asked for: a tags-only selector asks for none and costs nothing. A
/// stored document that no longer parses is left out, so fact leaves on it read false
/// rather than failing the whole evaluation.
pub async fn load_for_host(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
    sources: &BTreeSet<String>,
) -> anyhow::Result<HostFacts> {
    let repo = HostFactsRepo::new(&state.db);
    let mut stored = Vec::new();
    for source in sources {
        if let Some(s) = repo.get(tenant_id, host_id, source).await? {
            stored.push((source.clone(), s.facts_json));
        }
    }
    if stored.is_empty() {
        return Ok(HostFacts::new());
    }
    // Parsing documents of up to megabytes is CPU work: off the async workers.
    let host_id = host_id.to_owned();
    Ok(tokio::task::spawn_blocking(move || {
        stored
            .into_iter()
            .filter_map(|(source, json)| {
                parse_stored(&host_id, &source, &json).map(|doc| (source, doc))
            })
            .collect()
    })
    .await?)
}

/// How many rows a reader may hand a [`blocking_consumer`] ahead of it. The reader waits
/// once this many are queued, so a fleet streamed through one holds a handful of documents,
/// not all of them.
const PIPE_DEPTH: usize = 4;

/// A blocking thread running `consume` over the rows sent to the returned sender, and its
/// result once the sender is dropped. For folding a streamed query whose rows are documents
/// to parse — CPU work that has no place on an async worker, where it would stall every
/// other request sharing it.
fn blocking_consumer<T: Send + 'static, R: Send + 'static>(
    consume: impl FnOnce(&mut dyn Iterator<Item = T>) -> R + Send + 'static,
) -> (tokio::sync::mpsc::Sender<T>, tokio::task::JoinHandle<R>) {
    let (tx, mut rx) = tokio::sync::mpsc::channel(PIPE_DEPTH);
    let done = tokio::task::spawn_blocking(move || {
        consume(&mut std::iter::from_fn(move || rx.blocking_recv()))
    });
    (tx, done)
}

/// Every host in a tenant that holds a document from any of `sources`, with those
/// documents parsed, folded into `acc` by `f` one host at a time. One streamed query for the
/// fleet; only a few hosts' documents are held at once. Hosts holding none are not visited.
///
/// `f` runs on a blocking thread, with the parsing, which is why it owns what it folds into
/// and hands it back.
pub async fn fold_host_facts<S: Send + 'static>(
    state: &AppState,
    tenant_id: i64,
    sources: &BTreeSet<String>,
    acc: S,
    mut f: impl FnMut(&mut S, &str, &HostFacts) + Send + 'static,
) -> anyhow::Result<S> {
    if sources.is_empty() {
        // A tags-only selector: nothing to read, no thread to start.
        return Ok(acc);
    }
    let sources: Vec<String> = sources.iter().cloned().collect();
    let (tx, done) = blocking_consumer(
        move |rows: &mut dyn Iterator<Item = (String, String, String)>| {
            let mut acc = acc;
            // Rows arrive grouped by host: gather one host's documents, hand them over when the
            // next host starts.
            let mut current: Option<(String, HostFacts)> = None;
            for (host_id, source, json) in rows {
                if current.as_ref().map(|(h, _)| h.as_str()) != Some(host_id.as_str()) {
                    if let Some((h, facts)) = current.take() {
                        f(&mut acc, &h, &facts);
                    }
                    current = Some((host_id.clone(), HostFacts::new()));
                }
                if let (Some((_, facts)), Some(doc)) =
                    (current.as_mut(), parse_stored(&host_id, &source, &json))
                {
                    facts.insert(source, doc);
                }
            }
            if let Some((h, facts)) = current.take() {
                f(&mut acc, &h, &facts);
            }
            acc
        },
    );
    let read = HostFactsRepo::new(&state.db)
        .for_each_host_document(tenant_id, &sources, |host_id, source, json| {
            let tx = tx.clone();
            async move {
                // Fails only if the consumer is gone, which `done` reports.
                let _ = tx.send((host_id, source, json)).await;
            }
        })
        .await;
    drop(tx);
    let acc = done.await?;
    read?;
    Ok(acc)
}

fn parse_stored(host_id: &str, source: &str, json: &str) -> Option<Value> {
    match serde_json::from_str(json) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(%host_id, %source, error = %e, "stored facts document does not parse");
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
struct HistoryEntry {
    /// The first document this host sent: nothing to compare it with.
    initial: bool,
    /// Stored as `changes` and `truncated` beside `initial`.
    #[serde(flatten)]
    diff: FactsDiff,
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
            diff: FactsDiff::default(),
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
                diff: d,
            }
        }
    };
    serde_json::to_string(&entry).ok()
}

/// How the host's stored inventory relates to what the agent holds.
#[derive(Serialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FactsStatus {
    /// The agent never sent a hash: it predates facts, or has not polled since. Also what a
    /// stored document reads as when the agent has not confirmed holding it.
    NotReported,
    /// The agent has no fact set enabled.
    NothingEnabled,
    /// We hold what the agent holds.
    Current,
    /// The agent has a document and we have none yet; the upload follows its next poll.
    Pending,
    /// The agent has a newer document than the one shown; same.
    Outdated,
    /// The agent reports every fact set switched off; the inventory shown is cleared once
    /// it has said so for [`EMPTY_CLEAR_GRACE_SECS`].
    SwitchedOff,
    /// The agent's document was refused (too large, or malformed). It does not send that
    /// document again, so nothing is on its way until its inventory changes.
    Refused,
}

pub fn status(h: &FactsHashes) -> FactsStatus {
    match (h.held.as_deref(), h.reported.as_deref()) {
        (_, Some(EMPTY_FACTS_HASH))
            if matches!(h.held.as_deref(), None | Some(EMPTY_FACTS_HASH)) =>
        {
            FactsStatus::NothingEnabled
        }
        (Some(_), Some(EMPTY_FACTS_HASH)) => FactsStatus::SwitchedOff,
        // A document with no confirmation from the agent that it still holds it — the
        // reported-hash write failed, or something other than the agent wrote its slot — is
        // not "up to date".
        (_, None) => FactsStatus::NotReported,
        (Some(held), Some(reported)) if held == reported => FactsStatus::Current,
        // Refused while holding what it still reports: a newer hash is a new document,
        // which the agent does send.
        (_, Some(reported))
            if h.refused
                .as_ref()
                .is_some_and(|r| r.hash.as_deref() == Some(reported)) =>
        {
            FactsStatus::Refused
        }
        (None, Some(_)) => FactsStatus::Pending,
        (Some(_), Some(_)) => FactsStatus::Outdated,
    }
}

#[derive(Serialize)]
pub struct FactsChangesView {
    /// The history row's id: unique, where time and hash are not.
    pub id: i64,
    pub source: String,
    pub at: i64,
    pub facts_hash: String,
    pub initial: bool,
    /// Serialized as `changes` and `truncated` beside the fields above.
    #[serde(flatten)]
    pub diff: FactsDiff,
}

#[derive(Serialize)]
pub struct HostFactsView {
    /// Which source this is: always `agent`. Imported sources are in `others`.
    pub source: &'static str,
    pub status: FactsStatus,
    /// The stored document — its stored bytes, passed through rather than parsed and
    /// re-encoded — or null when the host never uploaded one, or when it is unreadable.
    pub facts: Option<Box<serde_json::value::RawValue>>,
    /// A document is stored but does not parse: `facts` is null for that reason, not
    /// because nothing was ever uploaded.
    pub unreadable: bool,
    pub facts_hash: Option<String>,
    /// What the agent last said it holds.
    pub reported_hash: Option<String>,
    /// Why nothing newer is coming, when the status is `refused`.
    pub refusal: Option<RefusalView>,
    /// When the agent collected it, by its own clock (ISO 8601).
    pub collected_at: Option<String>,
    /// When we received it.
    pub received_at: Option<i64>,
    pub size_bytes: Option<i64>,
    /// Newest first.
    pub changes: Vec<FactsChangesView>,
    /// The host's documents from every other source (imports), sorted by source.
    pub others: Vec<OtherFactsView>,
}

/// A host's document from a source other than the agent: an import. No hash exchange, so
/// no status; otherwise as [`HostFactsView`].
#[derive(Serialize)]
pub struct OtherFactsView {
    pub source: String,
    pub facts: Option<Box<serde_json::value::RawValue>>,
    pub unreadable: bool,
    pub facts_hash: String,
    pub collected_at: Option<String>,
    pub received_at: i64,
    pub size_bytes: i64,
    /// Newest first.
    pub changes: Vec<FactsChangesView>,
}

#[derive(Serialize)]
pub struct RefusalView {
    /// The HTTP status the upload was refused with: 413 too large, 400 malformed.
    pub status: u16,
    pub at: i64,
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
        let mut others = Vec::new();
        for o in repo
            .list_for_host_except(who.tenant_id, &host_id, AGENT_SOURCE)
            .await?
        {
            let changes = repo
                .list_changes(who.tenant_id, &host_id, &o.source, CHANGES_SHOWN)
                .await?;
            others.push((o, changes));
        }
        anyhow::Ok((hashes, stored, changes, others))
    }
    .await;
    let (hashes, stored, changes, others) = match loaded {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "host facts load failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let changes = changes_view(&host_id, changes);

    let status = status(&hashes);
    let refusal = match (&status, &hashes.refused) {
        (FactsStatus::Refused, Some(r)) => Some(RefusalView {
            status: r.status,
            at: r.at,
        }),
        _ => None,
    };
    let (facts, unreadable, facts_hash, collected_at, received_at, size_bytes) = match stored {
        None => (None, false, None, None, None, None),
        Some(s) => {
            let facts = raw_document(&host_id, &s.source, s.facts_json);
            let unreadable = facts.is_none();
            (
                facts,
                unreadable,
                Some(s.facts_hash),
                s.collected_at,
                Some(s.received_at),
                Some(s.size_bytes),
            )
        }
    };
    let view = HostFactsView {
        source: AGENT_SOURCE,
        status,
        facts,
        unreadable,
        facts_hash,
        reported_hash: hashes.reported,
        refusal,
        collected_at,
        received_at,
        size_bytes,
        changes,
        others: others
            .into_iter()
            .map(|(o, changes)| {
                let facts = raw_document(&host_id, &o.source, o.facts_json);
                OtherFactsView {
                    unreadable: facts.is_none(),
                    facts,
                    source: o.source,
                    facts_hash: o.facts_hash,
                    collected_at: o.collected_at,
                    received_at: o.received_at,
                    size_bytes: o.size_bytes,
                    changes: changes_view(&host_id, changes),
                }
            })
            .collect(),
    };
    Json(view).into_response()
}

/// A stored document as it goes out: validated, not re-encoded, so a document of megabytes
/// goes out as it was stored. `None` when it does not parse.
fn raw_document(
    host_id: &str,
    source: &str,
    json: String,
) -> Option<Box<serde_json::value::RawValue>> {
    match serde_json::value::RawValue::from_string(json) {
        Ok(raw) => Some(raw),
        Err(e) => {
            tracing::warn!(%host_id, %source, error = %e, "stored facts document does not parse");
            None
        }
    }
}

/// History rows as the page shows them.
fn changes_view(host_id: &str, rows: Vec<fleet_storage::FactChangeRow>) -> Vec<FactsChangesView> {
    rows.into_iter()
        .filter_map(|row| {
            // Left out rather than failing the page — but said, as a stored document that
            // no longer parses is.
            let entry: HistoryEntry = match serde_json::from_str(&row.changes_json) {
                Ok(e) => e,
                Err(e) => {
                    tracing::warn!(%host_id, history_id = row.id, error = %e, "stored facts history entry does not parse");
                    return None;
                }
            };
            Some(FactsChangesView {
                id: row.id,
                source: row.source,
                at: row.at,
                facts_hash: row.facts_hash,
                initial: entry.initial,
                diff: entry.diff,
            })
        })
        .collect()
}

// ---- Catalog: what the fleet's facts look like, for the selector editor -------------------

/// Paths listed per source. A path is listed once however many hosts have it, and records
/// in a list share their paths, so a real inventory has a few hundred; this bounds a
/// pathological one.
const MAX_CATALOG_PATHS: usize = 2_000;
/// Distinct values counted per path. Past this, new values are not counted, so a path with
/// a unique value per host (a serial number) does not grow without bound.
const MAX_DISTINCT_VALUES: usize = 500;
/// Values returned per path, most common first.
const MAX_VALUES_SHOWN: usize = 50;
/// Deepest path walked.
const MAX_CATALOG_DEPTH: usize = 16;

/// What sits at a path — which decides the tests that make sense on it.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    /// A string, number or boolean: `eq` / `in`.
    Scalar,
    /// A list: `has` a scalar element or a record id.
    List,
    /// A map: `has` a key, or step into it.
    Map,
    /// Different things on different hosts, or in different records of one host: no one
    /// test suits them all, so the editor does not pick one.
    Mixed,
}

impl PathKind {
    fn merge(self, other: PathKind) -> PathKind {
        if self == other {
            self
        } else {
            PathKind::Mixed
        }
    }
}

#[derive(Serialize)]
pub struct CatalogPath {
    /// In [`fleet_core::selector::FactPath`] form, with lists fanned out (no `[id]`).
    pub path: String,
    pub kind: PathKind,
    /// Hosts whose document has this path.
    pub hosts: usize,
    /// What a test on this path compares against — scalar values, or for a list its
    /// elements and record ids — with the number of hosts reporting each.
    pub values: Vec<(String, usize)>,
}

#[derive(Serialize)]
pub struct CatalogSource {
    pub source: String,
    /// Hosts holding a document from this source.
    pub hosts: usize,
    pub paths: Vec<CatalogPath>,
    /// True when [`MAX_CATALOG_PATHS`] cut the list short.
    pub truncated: bool,
}

#[derive(Serialize)]
pub struct FactsCatalog {
    pub sources: Vec<CatalogSource>,
}

/// Documents read per source for the catalog. The catalog is for picking paths and values,
/// and a few thousand hosts show every shape the fleet has; beyond that, the cost of reading
/// and parsing every inventory in the tenant buys nothing.
const MAX_CATALOG_HOSTS: i64 = 2_000;

/// How stale a catalog may be served after documents were stored. They are stored all day
/// — inventories move, and during a rollout hosts upload their first document one after
/// another — and each would otherwise have the next groups-page load read and parse every
/// document again, or throw away a build that one landed in the middle of. A minute's lag in
/// a path or value picker costs nothing; this bounds rebuilds to one a minute per tenant
/// however busy the fleet.
const CATALOG_REFRESH_SECS: i64 = 60;

/// What a change to a tenant's documents did to its catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogChange {
    /// A document was stored: served stale for up to [`CATALOG_REFRESH_SECS`].
    Stored,
    /// Hosts were deleted with their documents: rebuilt at once. An operator who just
    /// deleted a host does not expect to find it in the picker, and deletes are rare.
    Removed,
    /// An operator imported or deleted a source's documents: rebuilt at once, for the same
    /// reason — they expect the picker to show what they just did, and it is rare.
    Operator,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct CatalogGeneration {
    /// Every change.
    any: u64,
    /// Changes rebuilt at once ([`CatalogChange::Removed`], [`CatalogChange::Operator`]).
    removed: u64,
}

/// Built catalogs per tenant, each tagged with the tenant's generation when it was built.
/// Every change to a tenant's documents bumps it — [`store`] for a new document, the host
/// delete handlers for documents removed with their host.
#[derive(Default)]
pub struct CatalogCache {
    inner: std::sync::Mutex<CatalogCacheInner>,
    /// One build at a time per tenant: operators opening the groups page after a bump wait
    /// for the first rebuild instead of each reading every document again.
    building: std::sync::Mutex<HashMap<i64, Arc<tokio::sync::Mutex<()>>>>,
}

#[derive(Default)]
struct CatalogCacheInner {
    generations: HashMap<i64, CatalogGeneration>,
    /// Generation built against, when (unix seconds), and the catalog.
    built: HashMap<i64, (CatalogGeneration, i64, Arc<FactsCatalog>)>,
}

impl CatalogCache {
    fn build_lock(&self, tenant_id: i64) -> Arc<tokio::sync::Mutex<()>> {
        self.building
            .lock()
            .expect("catalog build lock map")
            .entry(tenant_id)
            .or_default()
            .clone()
    }

    /// A tenant's documents changed.
    pub fn bump(&self, tenant_id: i64, change: CatalogChange) {
        let mut inner = self.inner.lock().expect("catalog cache lock");
        let g = inner.generations.entry(tenant_id).or_default();
        g.any += 1;
        if change != CatalogChange::Stored {
            g.removed += 1;
        }
    }

    /// The cached catalog if it may still be served, else the generation to build against.
    /// Served when nothing changed since it was built; or when only documents were stored,
    /// it is younger than [`CATALOG_REFRESH_SECS`], and it lists some host — an empty one
    /// costs next to nothing to rebuild, and serving it would hide a tenant's first
    /// inventory for a minute.
    fn lookup(&self, tenant_id: i64, now: i64) -> Result<Arc<FactsCatalog>, CatalogGeneration> {
        let inner = self.inner.lock().expect("catalog cache lock");
        let current = inner
            .generations
            .get(&tenant_id)
            .copied()
            .unwrap_or_default();
        match inner.built.get(&tenant_id) {
            Some((g, at, c))
                if *g == current
                    || (g.removed == current.removed
                        && now - at < CATALOG_REFRESH_SECS
                        && c.sources.iter().any(|s| s.hosts > 0)) =>
            {
                Ok(c.clone())
            }
            _ => Err(current),
        }
    }

    /// Keep a catalog built against `generation`, whatever changed while it was built: it is
    /// tagged with what it saw, and [`Self::lookup`] decides when that is too old. Builds are
    /// one at a time per tenant, so this never replaces a newer one.
    fn keep(
        &self,
        tenant_id: i64,
        generation: CatalogGeneration,
        now: i64,
        catalog: Arc<FactsCatalog>,
    ) {
        self.inner
            .lock()
            .expect("catalog cache lock")
            .built
            .insert(tenant_id, (generation, now, catalog));
    }
}

/// One source's part of the catalog, fed a row at a time.
struct SourceBuild {
    acc: CatalogAcc,
    /// Documents folded in. One row per host and source (the primary key), so this is the
    /// host count — of hosts whose document parsed.
    hosts: usize,
    /// Rows offered, parsed or not.
    seen: i64,
    cap: i64,
}

impl SourceBuild {
    fn new(cap: i64) -> Self {
        Self {
            acc: CatalogAcc::default(),
            hosts: 0,
            seen: 0,
            cap,
        }
    }

    /// Fold in one row. The caller offers at most one row past the cap; that row is only
    /// evidence that the cap left something out, and is not read.
    fn offer(&mut self, host_id: &str, source: &str, json: &str) {
        self.seen += 1;
        if self.seen > self.cap {
            self.acc.truncated = true;
        } else if let Some(doc) = parse_stored(host_id, source, json) {
            self.acc.add_document(&doc);
            self.hosts += 1;
        }
    }

    fn finish(self, source: String) -> CatalogSource {
        self.acc.finish(source, self.hosts)
    }
}

struct PathAcc {
    kind: PathKind,
    hosts: usize,
    values: HashMap<String, usize>,
}

#[derive(Default)]
struct CatalogAcc {
    paths: BTreeMap<String, PathAcc>,
    truncated: bool,
}

impl CatalogAcc {
    fn add_document(&mut self, doc: &Value) {
        // Per host first, so a host with the same path in forty records counts once.
        let mut local: BTreeMap<String, (PathKind, BTreeSet<String>)> = BTreeMap::new();
        if let Value::Object(m) = doc {
            walk_children(m, "", false, 0, &mut local);
        }
        for (path, (kind, values)) in local {
            if !self.paths.contains_key(&path) && self.paths.len() >= MAX_CATALOG_PATHS {
                self.truncated = true;
                continue;
            }
            let acc = self.paths.entry(path).or_insert_with(|| PathAcc {
                kind,
                hosts: 0,
                values: HashMap::new(),
            });
            acc.kind = acc.kind.merge(kind);
            acc.hosts += 1;
            for v in values {
                let room = acc.values.len() < MAX_DISTINCT_VALUES;
                if let Some(n) = acc.values.get_mut(&v) {
                    *n += 1;
                } else if room {
                    acc.values.insert(v, 1);
                }
            }
        }
    }

    fn finish(self, source: String, hosts: usize) -> CatalogSource {
        let paths = self
            .paths
            .into_iter()
            .map(|(path, acc)| {
                let mut values: Vec<(String, usize)> = acc.values.into_iter().collect();
                values.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                values.truncate(MAX_VALUES_SHOWN);
                CatalogPath {
                    path,
                    kind: acc.kind,
                    hosts: acc.hosts,
                    values,
                }
            })
            .collect();
        CatalogSource {
            source,
            hosts,
            paths,
            truncated: self.truncated,
        }
    }
}

type LocalPaths = BTreeMap<String, (PathKind, BTreeSet<String>)>;

/// Record one path's kind, and a value under it when it is short enough to compare.
fn note(local: &mut LocalPaths, path: &str, kind: PathKind, value: Option<String>) {
    let entry = local
        .entry(path.to_owned())
        .or_insert_with(|| (kind, BTreeSet::new()));
    entry.0 = entry.0.merge(kind);
    if let Some(v) = value.filter(|v| v.len() <= MAX_VALUE_LEN) {
        entry.1.insert(v);
    }
}

/// `in_record`: `m` is a record of the list at `path`, whose fields the path fans out to.
fn walk_children(
    m: &serde_json::Map<String, Value>,
    path: &str,
    in_record: bool,
    depth: usize,
    local: &mut LocalPaths,
) {
    if depth >= MAX_CATALOG_DEPTH {
        return;
    }
    for (k, v) in m {
        // Only paths a selector can actually be written with: a key the grammar has no
        // spelling for is not offered.
        if let Some(child) = FactPath::child(path, k, in_record) {
            walk(v, &child, depth + 1, local);
        }
    }
}

fn walk(v: &Value, path: &str, depth: usize, local: &mut LocalPaths) {
    match v {
        Value::Null => {}
        Value::Object(m) => {
            // Its keys are what `has` compares against on a map.
            note(local, path, PathKind::Map, None);
            m.keys()
                .for_each(|k| note(local, path, PathKind::Map, Some(k.clone())));
            walk_children(m, path, false, depth, local);
        }
        Value::Array(items) => {
            note(local, path, PathKind::List, None);
            for item in items {
                match item {
                    // A record: offer its id to `has`, and fan out into its fields.
                    Value::Object(record) => {
                        let id = record.get("id").and_then(Value::as_str).map(str::to_owned);
                        note(local, path, PathKind::List, id);
                        walk_children(record, path, true, depth, local);
                    }
                    other => note(local, path, PathKind::List, scalar_text(other)),
                }
            }
        }
        scalar => note(local, path, PathKind::Scalar, scalar_text(scalar)),
    }
}

/// `GET /api/facts/catalog`: the paths the fleet's facts documents have, per source, and the
/// values seen at them. Backs the path and value pickers of the selector editor, the way the
/// host list's tags back the tag pickers.
///
/// Reads every document in the tenant, so it is for opening an editor, not for a poll path.
pub async fn catalog(State(state): State<AppState>, who: AuthedUser) -> Response {
    let now = now_unix();
    if let Ok(cached) = state.facts_catalog_cache.lookup(who.tenant_id, now) {
        return Json(&*cached).into_response();
    }
    // Stale: build it, but only one request per tenant at a time. The rest wait here and
    // then, as a rule, find what the first one built.
    let lock = state.facts_catalog_cache.build_lock(who.tenant_id);
    let _building = lock.lock().await;
    let generation = match state.facts_catalog_cache.lookup(who.tenant_id, now) {
        Ok(cached) => return Json(&*cached).into_response(),
        Err(generation) => generation,
    };
    let repo = HostFactsRepo::new(&state.db);
    let built = async {
        let mut sources: BTreeSet<String> = repo
            .list_sources(who.tenant_id)
            .await?
            .into_iter()
            .collect();
        // Always offered, so a group can be written before the first host uploads.
        sources.insert(AGENT_SOURCE.to_owned());
        let mut out = Vec::new();
        for source in sources {
            // Folded in on a blocking thread, a few documents in flight at a time. One row
            // past the cap is read only to learn whether the cap left anything out.
            let (tx, done) = {
                let source = source.clone();
                blocking_consumer(move |rows: &mut dyn Iterator<Item = (String, String)>| {
                    let mut build = SourceBuild::new(MAX_CATALOG_HOSTS);
                    for (host_id, json) in rows {
                        build.offer(&host_id, &source, &json);
                    }
                    build.finish(source)
                })
            };
            let read = repo
                .for_each_document(
                    who.tenant_id,
                    &source,
                    MAX_CATALOG_HOSTS + 1,
                    |host_id, json| {
                        let tx = tx.clone();
                        async move {
                            let _ = tx.send((host_id, json)).await;
                        }
                    },
                )
                .await;
            drop(tx);
            let built = done.await?;
            read?;
            out.push(built);
        }
        anyhow::Ok(FactsCatalog { sources: out })
    }
    .await;
    match built {
        Ok(c) => {
            let c = Arc::new(c);
            state
                .facts_catalog_cache
                .keep(who.tenant_id, generation, now, c.clone());
            Json(&*c).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "facts catalog failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog_of(docs: &[Value]) -> CatalogSource {
        let mut acc = CatalogAcc::default();
        docs.iter().for_each(|d| acc.add_document(d));
        acc.finish(AGENT_SOURCE.into(), docs.len())
    }

    fn path<'a>(c: &'a CatalogSource, p: &str) -> &'a CatalogPath {
        c.paths
            .iter()
            .find(|x| x.path == p)
            .unwrap_or_else(|| panic!("no {p}"))
    }

    #[test]
    fn the_catalog_lists_paths_kinds_and_values_per_host() {
        let a = serde_json::json!({
            "os": {"family": "linux", "build": "6.1"},
            "software": {"installed": [{"id": "bash", "version": "5.2", "x.y": "z"}, {"id": "vim", "version": "9.0"}]},
            "services": {"sshd": {"state": "running"}, "a.b": {"state": "x"}, "": {"state": "y"}},
            "": {"x": 1},
        });
        let b = serde_json::json!({
            "os": {"family": "windows", "build": ["19045"]},
            "software": {"installed": [{"id": "bash", "version": "5.1"}]},
            "net": {"addresses": ["10.0.0.1"]},
        });
        let c = catalog_of(&[a, b]);

        let fam = path(&c, "os.family");
        assert_eq!(fam.kind, PathKind::Scalar);
        assert_eq!(fam.hosts, 2);
        assert_eq!(
            fam.values,
            vec![("linux".to_owned(), 1), ("windows".to_owned(), 1)]
        );

        let installed = path(&c, "software.installed");
        assert_eq!(installed.kind, PathKind::List);
        // Record ids are what `has` compares against; bash is on both hosts.
        assert_eq!(installed.values[0], ("bash".to_owned(), 2));
        // Records fan out, and a host counts once however many records have the path.
        assert_eq!(path(&c, "software.installed.version").hosts, 2);
        assert_eq!(path(&c, "services").kind, PathKind::Map);
        assert!(path(&c, "services")
            .values
            .contains(&("sshd".to_owned(), 1)));
        assert_eq!(path(&c, "services.sshd.state").values[0].0, "running");
        assert_eq!(path(&c, "services[a.b].state").hosts, 1);
        // An empty key has no spelling at all, at the top or below it.
        assert!(c
            .paths
            .iter()
            .all(|p| !p.path.is_empty() && !p.path.contains("[]") && !p.path.contains("..")));
        // A dotted field of a list record has no spelling: `installed[x.y]` would pick the
        // record whose id is "x.y". It is not offered.
        assert!(c
            .paths
            .iter()
            .all(|p| !p.path.starts_with("software.installed[")));
        assert_eq!(
            path(&c, "net.addresses").values,
            vec![("10.0.0.1".to_owned(), 1)]
        );
        // A scalar on one host and a list on another: no single test suits both.
        assert_eq!(path(&c, "os.build").kind, PathKind::Mixed);
        assert!(!c.truncated);
    }

    fn h(held: Option<&str>, reported: Option<&str>) -> FactsHashes {
        FactsHashes {
            held: held.map(str::to_owned),
            reported: reported.map(str::to_owned),
            reported_since: None,
            refused: None,
        }
    }

    #[test]
    fn the_grace_rule_only_applies_to_an_empty_document_over_an_inventory() {
        let a = "a".repeat(64);
        let now = 10_000;
        let over = |held: Option<&str>, since: i64| FactsHashes {
            held: held.map(str::to_owned),
            reported: Some(EMPTY_FACTS_HASH.to_owned()),
            reported_since: Some(since),
            refused: None,
        };
        use EmptyOverInventory::*;
        assert_eq!(
            empty_over_inventory(&over(Some(&a), now), &a, now),
            NotApplicable
        );
        assert_eq!(
            empty_over_inventory(&over(None, 0), EMPTY_FACTS_HASH, now),
            NotApplicable
        );
        assert_eq!(
            empty_over_inventory(&over(Some(EMPTY_FACTS_HASH), 0), EMPTY_FACTS_HASH, now),
            NotApplicable
        );
        assert_eq!(
            empty_over_inventory(&over(Some(&a), now), EMPTY_FACTS_HASH, now),
            Pending
        );
        assert_eq!(
            empty_over_inventory(
                &over(Some(&a), now - EMPTY_CLEAR_GRACE_SECS),
                EMPTY_FACTS_HASH,
                now
            ),
            Due
        );
    }

    #[test]
    fn an_empty_report_clears_only_after_the_grace_period() {
        let a = "a".repeat(64);
        let now = 10_000;
        let hashes = |reported: &str, since: i64| FactsHashes {
            held: Some(a.clone()),
            reported: Some(reported.to_owned()),
            reported_since: Some(since),
            refused: None,
        };
        assert!(!empty_for_long_enough(&hashes(EMPTY_FACTS_HASH, now), now));
        assert!(!empty_for_long_enough(
            &hashes(EMPTY_FACTS_HASH, now - EMPTY_CLEAR_GRACE_SECS + 1),
            now
        ));
        assert!(empty_for_long_enough(
            &hashes(EMPTY_FACTS_HASH, now - EMPTY_CLEAR_GRACE_SECS),
            now
        ));
        // Long-standing, but not empty.
        assert!(!empty_for_long_enough(&hashes(&a, 0), now));
    }

    #[test]
    fn the_catalog_is_truncated_only_when_a_row_was_left_out() {
        let mut exact = SourceBuild::new(2);
        exact.offer("h1", AGENT_SOURCE, r#"{"os":{}}"#);
        exact.offer("h2", AGENT_SOURCE, "not json");
        let exact = exact.finish(AGENT_SOURCE.into());
        assert!(!exact.truncated, "exactly the cap is not truncated");
        assert_eq!(exact.hosts, 1, "only documents that parsed count as hosts");

        let mut over = SourceBuild::new(2);
        for h in ["h1", "h2", "h3"] {
            over.offer(h, AGENT_SOURCE, r#"{"os":{}}"#);
        }
        let over = over.finish(AGENT_SOURCE.into());
        assert!(over.truncated);
        assert_eq!(over.hosts, 2, "the row past the cap is not read");
    }

    #[test]
    fn stored_documents_rebuild_the_catalog_at_most_once_a_minute() {
        let c = CatalogCache::default();
        let catalog = |hosts| {
            let mut s = SourceBuild::new(10);
            for i in 0..hosts {
                s.offer(&format!("h{i}"), AGENT_SOURCE, "{}");
            }
            Arc::new(FactsCatalog {
                sources: vec![s.finish(AGENT_SOURCE.into())],
            })
        };
        let built = |c: &CatalogCache, now, hosts| {
            let Err(generation) = c.lookup(1, now) else {
                panic!("expected a rebuild")
            };
            c.keep(1, generation, now, catalog(hosts));
        };
        built(&c, 1_000, 1);
        assert!(c.lookup(1, 1_000).is_ok());

        // A document was stored: served as is for a while...
        c.bump(1, CatalogChange::Stored);
        assert!(c.lookup(1, 1_000 + CATALOG_REFRESH_SECS - 1).is_ok());
        // ...then rebuilt.
        assert!(c.lookup(1, 1_000 + CATALOG_REFRESH_SECS).is_err());

        // A build overtaken by a stored document while it ran is kept, tagged with what it
        // saw, and served within the window.
        let Err(generation) = c.lookup(1, 2_000) else {
            panic!("expected a rebuild")
        };
        c.bump(1, CatalogChange::Stored);
        c.keep(1, generation, 2_000, catalog(1));
        assert!(c.lookup(1, 2_000 + CATALOG_REFRESH_SECS - 1).is_ok());

        // A removal is not waited out.
        c.bump(1, CatalogChange::Removed);
        assert!(c.lookup(1, 2_001).is_err());

        // Nor is anything stored over a catalog of no hosts: a tenant's first inventory.
        built(&c, 3_000, 0);
        c.bump(1, CatalogChange::Stored);
        assert!(c.lookup(1, 3_001).is_err());

        // Tenants are separate.
        assert!(c.lookup(2, 3_001).is_err());
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
        // Until the grace period ends and the inventory is cleared.
        assert_eq!(
            status(&h(Some(&a), Some(EMPTY_FACTS_HASH))),
            FactsStatus::SwitchedOff
        );
        assert_eq!(status(&h(None, Some(&a))), FactsStatus::Pending);
        assert_eq!(status(&h(Some(&a), Some(&a))), FactsStatus::Current);
        assert_eq!(status(&h(Some(&a), Some(&b))), FactsStatus::Outdated);
        // Stored, but the agent never confirmed holding it.
        assert_eq!(status(&h(Some(&a), None)), FactsStatus::NotReported);
    }

    #[test]
    fn a_refusal_holds_only_while_the_agent_reports_the_refused_document() {
        let a = "a".repeat(64);
        let b = "b".repeat(64);
        let refused = |held: Option<&str>, reported: &str, refused: &str| FactsHashes {
            refused: Some(fleet_storage::FactsRefusal {
                hash: Some(refused.to_owned()),
                at: 1,
                status: 413,
            }),
            ..h(held, Some(reported))
        };
        assert_eq!(status(&refused(None, &a, &a)), FactsStatus::Refused);
        assert_eq!(status(&refused(Some(&b), &a, &a)), FactsStatus::Refused);
        // The agent moved on to another document, which it does send.
        assert_eq!(status(&refused(None, &b, &a)), FactsStatus::Pending);
        // What was refused once has since been stored.
        assert_eq!(status(&refused(Some(&a), &a, &a)), FactsStatus::Current);
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
        assert_eq!(e.diff.changes.len(), 1);
        assert_eq!(e.diff.changes[0].path, "os.family");
    }
}
