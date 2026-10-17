use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::facts::{FactsDiff, AGENT_SOURCE, EMPTY_FACTS_HASH};
use fleet_storage::{FactsHashes, HostFactsRepo, HostRepo};
use serde::Serialize;

use super::store::HistoryEntry;
use crate::auth::AuthedUser;
use crate::AppState;

/// History entries returned with a host's facts.
const CHANGES_SHOWN: i64 = 50;

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

#[cfg(test)]
mod tests {
    use super::*;

    fn h(held: Option<&str>, reported: Option<&str>) -> FactsHashes {
        FactsHashes {
            held: held.map(str::to_owned),
            reported: reported.map(str::to_owned),
            reported_since: None,
            refused: None,
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
}
