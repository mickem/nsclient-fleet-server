use fleet_core::facts::{self, FactsDiff};
use fleet_core::selector::HostFacts;
use fleet_storage::{HostFactsRepo, NewFacts, ReplaceOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeSet;
use std::sync::Arc;

use super::CatalogChange;
use crate::AppState;

/// History entries kept per host.
const KEEP_HISTORY: i64 = 100;

/// Changes listed per history entry. The rest are counted: a host that installed a few
/// hundred packages in one go is one entry saying so, not a history row the size of the
/// document.
const MAX_CHANGES_PER_ENTRY: usize = 200;

/// Attempts at storing a document when another write keeps replacing it underneath.
const STORE_ATTEMPTS: usize = 3;

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
pub(super) fn blocking_consumer<T: Send + 'static, R: Send + 'static>(
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

pub(super) fn parse_stored(host_id: &str, source: &str, json: &str) -> Option<Value> {
    match serde_json::from_str(json) {
        Ok(v) => Some(v),
        Err(e) => {
            tracing::warn!(%host_id, %source, error = %e, "stored facts document does not parse");
            None
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(super) struct HistoryEntry {
    /// The first document this host sent: nothing to compare it with.
    pub(super) initial: bool,
    /// Stored as `changes` and `truncated` beside `initial`.
    #[serde(flatten)]
    pub(super) diff: FactsDiff,
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

#[cfg(test)]
mod tests {
    use super::*;

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
