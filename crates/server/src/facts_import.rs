//! Facts import: an operator's file of rows (a CMDB export, a spreadsheet), each row a
//! facts document for one host, stored under the source `import:<name>`.
//!
//! Two steps, with the same body:
//!
//! * `POST /api/facts/import/resolve` ([`resolve`]) matches every row to a host and writes
//!   nothing.
//! * `POST /api/facts/import` ([`commit`]) matches again — what the operator saw may be out
//!   of date — refuses with 409 if any row it is asked to store does not land on exactly one
//!   host of its own, and otherwise stores each document through [`crate::facts::store`],
//!   the one write path for facts.
//!
//! Keys are import-time only: they find the host, and the document is then stored by host
//! id. The matching itself is [`fleet_core::facts_import`]; this module gathers each host's
//! values for the key targets, which needs the database.
//!
//! Also here: deleting one host's document from a source, and a source tenant-wide.

// The helpers below return a ready `Response` as their error, once per request: large, but
// not worth a Box.
#![allow(clippy::result_large_err)]

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::facts::{sha256_hex, valid_source, AGENT_SOURCE, MAX_COLLECTED_AT_LEN};
use fleet_core::facts_import::{
    fact_key_values, import_source, resolve_rows, valid_import_name, HostField, KeyIndex,
    KeyTarget, Normalize, Resolution, RowKey, MAX_IMPORT_KEYS, MAX_IMPORT_ROWS,
};
use fleet_core::selector::{scalar_text, FactPath};
use fleet_core::Host;
use fleet_storage::{HostFactsRepo, HostRepo, HostTagsRepo, ReplaceOutcome};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use crate::auth::AuthedUser;
use crate::facts::{CatalogChange, MAX_FACTS_BODY_BYTES};
use crate::AppState;

/// Largest import request body. Rows are capped at [`MAX_IMPORT_ROWS`] and each document at
/// [`MAX_FACTS_BODY_BYTES`]; this bounds the whole.
pub const MAX_IMPORT_BODY_BYTES: usize = 64 * 1024 * 1024;

/// Absent hosts listed in a resolve answer; the rest are only counted.
const MAX_ABSENT_SHOWN: usize = 500;

#[derive(Deserialize)]
struct ImportBody {
    name: String,
    keys: Vec<KeyTarget>,
    #[serde(default)]
    normalize: Normalize,
    #[serde(default)]
    collected_at: Option<String>,
    rows: Vec<ImportRow>,
    /// Commit only: row indices left out.
    #[serde(default)]
    skip: Vec<usize>,
    /// Commit only: delete this source's document from every host not in the file.
    #[serde(default)]
    prune: bool,
}

#[derive(Deserialize)]
struct ImportRow {
    /// Positional, one per key target. Strings as a rule; a number or boolean is taken by
    /// its JSON text, null as an empty cell.
    #[serde(default)]
    keys: Vec<Value>,
    facts: Value,
    /// An explicit host, chosen by the operator: skips matching.
    #[serde(default)]
    host_id: Option<String>,
}

/// A validated request, documents serialized and hashed.
struct Prepared {
    source: String,
    keys: Vec<KeyTarget>,
    normalize: Normalize,
    collected_at: Option<String>,
    rows: Vec<PreparedRow>,
    skip: HashSet<usize>,
    prune: bool,
}

struct PreparedRow {
    keys: Vec<String>,
    host_id: Option<String>,
    hash: String,
    json: Arc<str>,
}

fn bad(msg: impl Into<String>) -> Response {
    (StatusCode::BAD_REQUEST, msg.into()).into_response()
}

fn internal() -> Response {
    (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
}

/// Parse and validate a request body. CPU work on up to 64 MiB: run off the async workers.
fn prepare(body: &[u8]) -> Result<Prepared, Response> {
    let body: ImportBody =
        serde_json::from_slice(body).map_err(|e| bad(format!("invalid import body: {e}")))?;
    if !valid_import_name(&body.name) {
        return Err(bad(
            "invalid import name: lowercase letters, digits and _ . - only, starting with a \
             letter, no ':', not \"agent\", at most 57 characters",
        ));
    }
    if body.keys.is_empty() || body.keys.len() > MAX_IMPORT_KEYS {
        return Err(bad(format!(
            "between 1 and {MAX_IMPORT_KEYS} keys are required"
        )));
    }
    for k in &body.keys {
        k.validate().map_err(bad)?;
    }
    if body.rows.is_empty() {
        return Err(bad("no rows"));
    }
    if body.rows.len() > MAX_IMPORT_ROWS {
        return Err(bad(format!("too many rows (max {MAX_IMPORT_ROWS})")));
    }
    let n_rows = body.rows.len();
    if let Some(i) = body.skip.iter().find(|&&i| i >= n_rows) {
        return Err(bad(format!("skip index {i} is out of range")));
    }
    let mut rows = Vec::with_capacity(n_rows);
    for (i, row) in body.rows.into_iter().enumerate() {
        let host_id = row.host_id.filter(|h| !h.is_empty());
        if host_id.is_none() && row.keys.len() != body.keys.len() {
            return Err(bad(format!(
                "row {i}: {} key values for {} keys",
                row.keys.len(),
                body.keys.len()
            )));
        }
        let keys = row
            .keys
            .iter()
            .map(|v| {
                match v {
                    Value::Null => Some(String::new()),
                    other => scalar_text(other),
                }
                .ok_or_else(|| bad(format!("row {i}: key values must be strings")))
            })
            .collect::<Result<Vec<_>, _>>()?;
        if !row.facts.is_object() {
            return Err(bad(format!("row {i}: facts must be a JSON object")));
        }
        let json = serde_json::to_string(&row.facts).map_err(|_| internal())?;
        if json.len() > MAX_FACTS_BODY_BYTES {
            return Err((
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("row {i}: facts document larger than {MAX_FACTS_BODY_BYTES} bytes"),
            )
                .into_response());
        }
        rows.push(PreparedRow {
            keys,
            host_id,
            hash: sha256_hex(json.as_bytes()),
            json: Arc::from(json),
        });
    }
    let collected_at = body
        .collected_at
        .map(|c| {
            c.trim()
                .chars()
                .take(MAX_COLLECTED_AT_LEN)
                .collect::<String>()
        })
        .filter(|c| !c.is_empty());
    Ok(Prepared {
        source: import_source(&body.name),
        keys: body.keys,
        normalize: body.normalize,
        collected_at,
        rows,
        skip: body.skip.into_iter().collect(),
        prune: body.prune,
    })
}

/// The checks every import route shares: the role, the content type (taken as bytes, the
/// body skips axum's `Json` check, which is part of the CSRF defence), then the body.
async fn accept(who: &AuthedUser, headers: &HeaderMap, body: Bytes) -> Result<Prepared, Response> {
    if !who.role.can_write_config() {
        return Err(crate::auth::forbidden("change configuration"));
    }
    let json = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(';')
                .next()
                .is_some_and(|m| m.trim().eq_ignore_ascii_case("application/json"))
        });
    if !json {
        return Err((
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "expected Content-Type: application/json",
        )
            .into_response());
    }
    match tokio::task::spawn_blocking(move || prepare(&body)).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "import body parse task failed");
            Err(internal())
        }
    }
}

/// The tenant's hosts, and an index of their values for each key target.
async fn build_index(
    state: &AppState,
    tenant_id: i64,
    keys: &[KeyTarget],
    normalize: Normalize,
) -> anyhow::Result<(Vec<Host>, KeyIndex)> {
    let hosts = HostRepo::new(&state.db).list(tenant_id).await?;
    let by_id: HashMap<&str, usize> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| (h.id.as_str(), i))
        .collect();
    let mut index = KeyIndex::new(keys.len(), normalize);
    let mut fact_targets: Vec<(usize, String, FactPath)> = Vec::new();
    for (t, target) in keys.iter().enumerate() {
        match target {
            KeyTarget::Host { field } => {
                for (i, h) in hosts.iter().enumerate() {
                    match field {
                        HostField::Id => index.add(t, i, &h.id),
                        HostField::Hostname => {
                            if let Some(name) = &h.hostname {
                                index.add(t, i, name)
                            }
                        }
                    }
                }
            }
            KeyTarget::Tag { key } => {
                for (host_id, value) in HostTagsRepo::new(&state.db)
                    .values_for_key(tenant_id, key)
                    .await?
                {
                    if let Some(&i) = by_id.get(host_id.as_str()) {
                        index.add(t, i, &value);
                    }
                }
            }
            KeyTarget::Fact { source, path } => {
                fact_targets.push((t, source.clone(), path.clone()));
            }
        }
    }
    if !fact_targets.is_empty() {
        // One pass over the fleet's documents for every fact target together.
        let sources: BTreeSet<String> = fact_targets.iter().map(|(_, s, _)| s.clone()).collect();
        let values = crate::facts::fold_host_facts(
            state,
            tenant_id,
            &sources,
            Vec::new(),
            move |acc: &mut Vec<(usize, String, String)>, host_id, facts| {
                for (t, source, path) in &fact_targets {
                    if let Some(doc) = facts.get(source) {
                        for v in fact_key_values(path, doc) {
                            acc.push((*t, host_id.to_owned(), v));
                        }
                    }
                }
            },
        )
        .await?;
        for (t, host_id, v) in values {
            if let Some(&i) = by_id.get(host_id.as_str()) {
                index.add(t, i, &v);
            }
        }
    }
    Ok((hosts, index))
}

/// Match every row. Skipped rows are left out before duplicates are detected, in resolve
/// and commit alike, so resolve shows exactly what commit will enforce.
fn match_rows(hosts: &[Host], index: &KeyIndex, p: &Prepared) -> Vec<Resolution> {
    let by_id: HashMap<&str, usize> = hosts
        .iter()
        .enumerate()
        .map(|(i, h)| (h.id.as_str(), i))
        .collect();
    let rows: Vec<RowKey<'_>> = p
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            if p.skip.contains(&i) {
                RowKey::Skipped
            } else if let Some(h) = &r.host_id {
                RowKey::Host(by_id.get(h.as_str()).copied())
            } else {
                RowKey::Keys(&r.keys)
            }
        })
        .collect();
    resolve_rows(index, &rows)
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum RowStatus {
    Matched {
        host_id: String,
        hostname: Option<String>,
    },
    Ambiguous {
        host_ids: Vec<String>,
    },
    Unmatched,
    Duplicate {
        host_id: String,
        of: usize,
    },
    /// Left out by `skip`: does not cover a host.
    Skipped,
}

#[derive(Serialize)]
struct RowView {
    index: usize,
    #[serde(flatten)]
    status: RowStatus,
}

fn row_view(hosts: &[Host], index: usize, r: &Resolution) -> RowView {
    let status = match r {
        Resolution::Matched(h) => RowStatus::Matched {
            host_id: hosts[*h].id.clone(),
            hostname: hosts[*h].hostname.clone(),
        },
        Resolution::Ambiguous(hs) => RowStatus::Ambiguous {
            host_ids: hs.iter().map(|&h| hosts[h].id.clone()).collect(),
        },
        Resolution::Unmatched => RowStatus::Unmatched,
        Resolution::Duplicate { host, of } => RowStatus::Duplicate {
            host_id: hosts[*host].id.clone(),
            of: *of,
        },
        Resolution::Skipped => RowStatus::Skipped,
    };
    RowView { index, status }
}

#[derive(Serialize, Default)]
struct ResolveStats {
    matched: usize,
    ambiguous: usize,
    unmatched: usize,
    duplicate: usize,
    skipped: usize,
}

#[derive(Serialize)]
struct AbsentHost {
    id: String,
    hostname: Option<String>,
    /// The host currently holds a document from this source: what `prune` would delete.
    has_source: bool,
}

#[derive(Serialize)]
struct ResolveResponse {
    source: String,
    rows: Vec<RowView>,
    /// Tenant hosts no row resolved to, by hostname; at most [`MAX_ABSENT_SHOWN`].
    absent: Vec<AbsentHost>,
    absent_total: usize,
    stats: ResolveStats,
}

/// `POST /api/facts/import/resolve`: match every row to a host; write nothing.
pub async fn resolve(
    State(state): State<AppState>,
    who: AuthedUser,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let p = match accept(&who, &headers, body).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let loaded = async {
        let (hosts, index) = build_index(&state, who.tenant_id, &p.keys, p.normalize).await?;
        let holding: HashSet<String> = HostFactsRepo::new(&state.db)
            .hosts_with_source(who.tenant_id, &p.source)
            .await?
            .into_iter()
            .collect();
        anyhow::Ok((hosts, index, holding))
    }
    .await;
    let (hosts, index, holding) = match loaded {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "facts import resolve failed");
            return internal();
        }
    };
    let resolved = match_rows(&hosts, &index, &p);

    let mut stats = ResolveStats::default();
    let mut present = HashSet::new();
    let mut rows = Vec::with_capacity(resolved.len());
    for (i, r) in resolved.iter().enumerate() {
        match r {
            Resolution::Matched(h) => {
                stats.matched += 1;
                present.insert(*h);
            }
            Resolution::Ambiguous(_) => stats.ambiguous += 1,
            Resolution::Unmatched => stats.unmatched += 1,
            Resolution::Duplicate { .. } => stats.duplicate += 1,
            Resolution::Skipped => stats.skipped += 1,
        }
        rows.push(row_view(&hosts, i, r));
    }
    let mut absent: Vec<&Host> = hosts
        .iter()
        .enumerate()
        .filter(|(i, _)| !present.contains(i))
        .map(|(_, h)| h)
        .collect();
    // Hosts holding the source first — what a prune would touch — then by name.
    absent.sort_by(|a, b| {
        let held = |h: &Host| !holding.contains(&h.id);
        held(a)
            .cmp(&held(b))
            .then_with(|| a.hostname.is_none().cmp(&b.hostname.is_none()))
            .then_with(|| a.hostname.cmp(&b.hostname))
            .then_with(|| a.id.cmp(&b.id))
    });
    let absent_total = absent.len();
    let absent = absent
        .into_iter()
        .take(MAX_ABSENT_SHOWN)
        .map(|h| AbsentHost {
            id: h.id.clone(),
            hostname: h.hostname.clone(),
            has_source: holding.contains(&h.id),
        })
        .collect();
    Json(ResolveResponse {
        source: p.source,
        rows,
        absent,
        absent_total,
        stats,
    })
    .into_response()
}

#[derive(Serialize)]
struct CommitResponse {
    source: String,
    /// Documents written.
    stored: usize,
    /// Rows whose document the host already held: nothing written.
    unchanged: usize,
    skipped: usize,
    /// Documents of this source deleted from hosts not in the file.
    pruned: usize,
    /// Rows not stored because their host went away, or kept being written underneath, in
    /// the meantime.
    failed: usize,
}

/// `POST /api/facts/import`: store every row's document for its host.
pub async fn commit(
    State(state): State<AppState>,
    who: AuthedUser,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let p = match accept(&who, &headers, body).await {
        Ok(p) => p,
        Err(r) => return r,
    };
    let (hosts, index) = match build_index(&state, who.tenant_id, &p.keys, p.normalize).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "facts import index failed");
            return internal();
        }
    };
    let resolved = match_rows(&hosts, &index, &p);
    let offending: Vec<RowView> = resolved
        .iter()
        .enumerate()
        .filter(|(_, r)| !matches!(r, Resolution::Matched(_) | Resolution::Skipped))
        .map(|(i, r)| row_view(&hosts, i, r))
        .collect();
    if !offending.is_empty() {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({ "error": "unresolved rows", "rows": offending })),
        )
            .into_response();
    }

    let mut out = CommitResponse {
        source: p.source.clone(),
        stored: 0,
        unchanged: 0,
        skipped: p.skip.len(),
        pruned: 0,
        failed: 0,
    };
    let mut present = HashSet::new();
    let mut error = None;
    for (row, r) in p.rows.iter().zip(&resolved) {
        let Resolution::Matched(h) = r else { continue };
        let host_id = &hosts[*h].id;
        present.insert(host_id.as_str());
        match crate::facts::store(
            &state,
            who.tenant_id,
            host_id,
            &p.source,
            &row.hash,
            row.json.clone(),
            p.collected_at.as_deref(),
        )
        .await
        {
            Ok(ReplaceOutcome::Stored) => out.stored += 1,
            Ok(ReplaceOutcome::Unchanged) => out.unchanged += 1,
            Ok(outcome @ (ReplaceOutcome::Conflict | ReplaceOutcome::NoHost)) => {
                tracing::warn!(%host_id, ?outcome, "imported facts document not stored");
                out.failed += 1;
            }
            Err(e) => {
                error = Some(e);
                break;
            }
        }
    }
    if error.is_none() && p.prune {
        match HostFactsRepo::new(&state.db)
            .hosts_with_source(who.tenant_id, &p.source)
            .await
        {
            Ok(holding) => {
                for host_id in holding.iter().filter(|h| !present.contains(h.as_str())) {
                    match crate::facts::remove(&state, who.tenant_id, host_id, &p.source, false)
                        .await
                    {
                        Ok(true) => out.pruned += 1,
                        Ok(false) => {}
                        Err(e) => {
                            error = Some(e);
                            break;
                        }
                    }
                }
            }
            Err(e) => error = Some(e),
        }
    }
    if out.stored > 0 || out.pruned > 0 {
        // Once for the import, and at once: the operator expects the new source in the
        // pickers now, not within the minute stored documents are otherwise served stale.
        state
            .facts_catalog_cache
            .bump(who.tenant_id, CatalogChange::Operator);
    }
    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "facts.imported",
        "facts_source",
        &p.source,
        Some(&serde_json::json!({
            "rows": p.rows.len(),
            "stored": out.stored,
            "unchanged": out.unchanged,
            "skipped": out.skipped,
            "pruned": out.pruned,
            "failed": out.failed,
            "prune": p.prune,
            "keys": p.keys,
            "complete": error.is_none(),
        })),
    )
    .await;
    if let Some(e) = error {
        tracing::error!(error = %e, "facts import failed part way");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "import failed part way: {} stored, {} pruned before the failure",
                out.stored, out.pruned
            ),
        )
            .into_response();
    }
    Json(out).into_response()
}

/// A source named in a delete path: a valid name that is not the agent's.
fn deletable_source(source: &str) -> Result<(), Response> {
    if source == AGENT_SOURCE {
        return Err(bad(
            "the agent's own facts cannot be deleted; they are replaced by its next upload",
        ));
    }
    if !valid_source(source) {
        return Err(bad("invalid facts source"));
    }
    Ok(())
}

/// `DELETE /api/hosts/:id/facts/:source`: delete one host's document from an imported
/// source, with its history.
pub async fn delete_host_source(
    State(state): State<AppState>,
    who: AuthedUser,
    Path((host_id, source)): Path<(String, String)>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if let Err(r) = deletable_source(&source) {
        return r;
    }
    match HostRepo::new(&state.db).get(who.tenant_id, &host_id).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host get failed");
            return internal();
        }
    }
    match crate::facts::remove(&state, who.tenant_id, &host_id, &source, true).await {
        Ok(true) => {
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "facts.deleted",
                "host",
                &host_id,
                Some(&serde_json::json!({ "source": source })),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            "the host holds no document from this source",
        )
            .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "facts delete failed");
            internal()
        }
    }
}

/// `DELETE /api/facts/sources/:source`: delete an imported source from every host.
pub async fn delete_source(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(source): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if let Err(r) = deletable_source(&source) {
        return r;
    }
    match crate::facts::remove_source(&state, who.tenant_id, &source).await {
        Ok(deleted) => {
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "facts.source_deleted",
                "facts_source",
                &source,
                Some(&serde_json::json!({ "deleted": deleted })),
            )
            .await;
            Json(serde_json::json!({ "deleted": deleted })).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "facts source delete failed");
            internal()
        }
    }
}
