use axum::{
    http::{HeaderName, HeaderValue},
    response::Response,
};
use fleet_core::facts::{self, AGENT_SOURCE, EMPTY_FACTS_HASH, FACTS_HASH_HEADER, FACTS_HASH_NONE};
use fleet_core::time::now_unix;
use fleet_storage::{FactsHashes, HostFactsRepo, ReplaceOutcome};
use std::sync::Arc;

use super::store;
use crate::AppState;

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
pub(super) enum EmptyOverInventory {
    /// Not that case: `hash` is a real document, or there is nothing to clear.
    NotApplicable,
    /// The agent has not said so for the whole grace period yet: keep the inventory.
    Pending,
    /// It has: clear the inventory.
    Due,
}

pub(super) fn empty_over_inventory(h: &FactsHashes, hash: &str, now: i64) -> EmptyOverInventory {
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

/// Attach the header to a response, if there is one to attach.
pub fn with_header(mut response: Response, value: Option<HeaderValue>) -> Response {
    if let Some(v) = value {
        response.headers_mut().insert(header_name(), v);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
