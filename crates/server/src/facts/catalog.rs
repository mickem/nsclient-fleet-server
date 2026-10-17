use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::facts::AGENT_SOURCE;
use fleet_core::selector::{scalar_text, FactPath, MAX_VALUE_LEN};
use fleet_core::time::now_unix;
use fleet_storage::HostFactsRepo;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use super::store::{blocking_consumer, parse_stored};
use crate::auth::AuthedUser;
use crate::AppState;

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
}
