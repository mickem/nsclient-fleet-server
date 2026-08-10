//! Compute a host's desired state by walking tags → groups → bundles → host override,
//! priority-ordered merge, hash. Phase 5 replaces the placeholder used in Phase 4.
//!
//! Results are memoized per host against the tenant's `config_version` (Phase 9). Every
//! input to the computation — tags, groups and their selectors, bundle assignments, bundle
//! rows, host overrides — is behind a mutation path that bumps that counter, so a stale
//! entry cannot outlive a change. See `DesiredStateCache`.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use fleet_core::merge::{canonical_string, merge_patch};
use fleet_core::selector::Selector;
use fleet_core::time::now_unix;
use fleet_storage::{
    BundleAssignmentsRepo, GroupsRepo, HostOverridesRepo, HostTagsRepo, TenantRepo,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::AppState;

#[derive(Debug, Clone)]
pub struct DesiredBundle {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub signature: String,
    pub priority: i64,
}

#[derive(Debug, Clone)]
pub struct DesiredState {
    pub state_hash: String,
    pub merged_config: Value,
    pub bundles: Vec<DesiredBundle>,
}

/// Beyond this many live entries the cache starts reclaiming. One entry per host that has
/// polled, so the ceiling is really fleet size; this only guards against pathology
/// (host churn, a deleted tenant's rows lingering).
const MAX_ENTRIES: usize = 100_000;

/// Entries untouched for this long are dropped first when reclaiming. Comfortably longer
/// than any tier's poll interval, so a live agent never loses its entry to pruning.
const IDLE_TTL_SECS: i64 = 3600;

struct Entry {
    config_version: i64,
    state: DesiredState,
    /// Atomic so a cache hit only needs the read lock.
    last_used: AtomicI64,
}

/// Memoized desired state, keyed by `(tenant_id, host_id)` and validated against the
/// tenant's `config_version`.
///
/// The plan called for a key of `(host_id, config_version)`. Storing the version *inside*
/// the entry instead is the same memoization with a bounded footprint: a version bump
/// replaces one entry per host rather than orphaning the old one, so the map never grows
/// with the number of configuration changes.
///
/// Correctness rests entirely on `config_version` being bumped by every path that can
/// change a computed input. If you add a mutation that touches tags, groups, selectors,
/// bundle assignments, bundle rows, or host overrides and do not bump it, agents will be
/// served stale configuration until something else bumps the counter.
#[derive(Default)]
pub struct DesiredStateCache {
    entries: RwLock<HashMap<(i64, String), Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
}

impl DesiredStateCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, tenant_id: i64, host_id: &str, config_version: i64) -> Option<DesiredState> {
        let map = self.entries.read().expect("desired-state cache lock");
        // Cheap borrow-key lookup would need a custom Borrow impl; hosts poll at most a few
        // times a minute, so one key allocation here is not worth the complexity.
        let hit = map.get(&(tenant_id, host_id.to_string())).and_then(|e| {
            (e.config_version == config_version).then(|| {
                e.last_used.store(now_unix(), Ordering::Relaxed);
                e.state.clone()
            })
        });
        match hit {
            Some(s) => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(s)
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn put(&self, tenant_id: i64, host_id: &str, config_version: i64, state: &DesiredState) {
        let mut map = self.entries.write().expect("desired-state cache lock");
        if map.len() >= MAX_ENTRIES {
            let cutoff = now_unix() - IDLE_TTL_SECS;
            let before = map.len();
            map.retain(|_, e| e.last_used.load(Ordering::Relaxed) >= cutoff);
            if map.len() >= MAX_ENTRIES {
                // Nothing was idle. Rather than grow without bound, start over and pay the
                // recompute; this should never happen on a single-VM fleet.
                map.clear();
            }
            tracing::info!(
                before,
                after = map.len(),
                "desired-state cache reclaimed entries"
            );
        }
        map.insert(
            (tenant_id, host_id.to_string()),
            Entry {
                config_version,
                state: state.clone(),
                last_used: AtomicI64::new(now_unix()),
            },
        );
    }

    /// Drop a host's entry. `config_version` covers every *configuration* change, but not a
    /// host disappearing — deleting a host does not change the tenant's config.
    pub fn invalidate_host(&self, tenant_id: i64, host_id: &str) {
        self.entries
            .write()
            .expect("desired-state cache lock")
            .remove(&(tenant_id, host_id.to_string()));
    }

    /// `(hits, misses)` since startup. Exposed so the cost of the lazy recompute can be
    /// judged from data rather than guessed at.
    pub fn stats(&self) -> (u64, u64) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.read().expect("lock").len()
    }
}

/// Desired state for a host, served from cache when the tenant's configuration has not
/// moved since it was computed.
///
/// Callers that have already loaded the tenant row should pass its `config_version` to
/// [`compute_desired_state_at`] instead — this variant re-reads it.
pub async fn compute_desired_state(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
) -> Result<DesiredState> {
    let config_version = match TenantRepo::new(&state.db).get(tenant_id).await? {
        Some(t) => t.config_version,
        None => return Err(anyhow!("tenant {tenant_id} not found")),
    };
    compute_desired_state_at(state, tenant_id, host_id, config_version).await
}

/// As [`compute_desired_state`], for callers that already know the tenant's
/// `config_version` — the agent poll path, which loads the tenant row anyway for its tier.
pub async fn compute_desired_state_at(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
    config_version: i64,
) -> Result<DesiredState> {
    if let Some(cached) = state
        .desired_state_cache
        .get(tenant_id, host_id, config_version)
    {
        return Ok(cached);
    }

    let computed = compute_uncached(state, tenant_id, host_id).await?;

    // Store against the version we were handed. If a bump landed while we were computing,
    // this entry is already stale-by-key and the next poll recomputes — the same outcome as
    // having no cache, never a stale answer.
    state
        .desired_state_cache
        .put(tenant_id, host_id, config_version, &computed);
    Ok(computed)
}

/// The actual walk. Kept separate so tests and benchmarks can measure it without the cache.
pub async fn compute_uncached(
    state: &AppState,
    tenant_id: i64,
    host_id: &str,
) -> Result<DesiredState> {
    // 1. Collect host tags (manual + agent, both sources).
    let tags = HostTagsRepo::new(&state.db)
        .map_for_host(tenant_id, host_id)
        .await?;

    // 2. Find groups whose selector matches the host.
    let groups = GroupsRepo::new(&state.db).list(tenant_id).await?;
    let matching_group_ids: Vec<String> = groups
        .iter()
        .filter_map(|g| {
            let selector_v: Value = serde_json::from_str(&g.selector_json).ok()?;
            let selector = Selector::from_json(&selector_v).ok()?;
            if selector.matches(&tags) {
                Some(g.id.clone())
            } else {
                None
            }
        })
        .collect();

    // 3. Collect (bundle, priority) for those groups.
    let mut group_bundles = BundleAssignmentsRepo::new(&state.db)
        .list_for_groups(tenant_id, &matching_group_ids)
        .await?;
    // Sort ascending by priority so layers apply in order (later = higher priority wins).
    group_bundles.sort_by_key(|(_, p)| *p);

    // 4. Build the merged config: empty {} → apply each bundle's config patch in order.
    //    The bundle's "config patch" = the JSON we *would* read from config.json inside the
    //    bundle. For Phase 5 we don't unpack the zip server-side; we keep an in-memory
    //    indirection by storing the patch on the row at upload time. Until that's wired,
    //    bundles contribute nothing to the merged config and an agent's config_json is {}.
    //    The agent applies bundles itself once it downloads them. The state_hash here
    //    therefore reflects the *bundle set* (id + sha256 + priority), not the merged
    //    config bytes. Document this in the response so agents know.
    let mut merged = Value::Object(serde_json::Map::new());

    // 5. Layer in host override (priority 1000+ by default).
    let override_priority: Option<(i64, Value)> = match HostOverridesRepo::new(&state.db)
        .get(tenant_id, host_id)
        .await?
    {
        Some(o) => {
            let plaintext = state
                .config
                .master_key
                .decrypt(&o.patch_encrypted)
                .map_err(|e| anyhow!("override decrypt: {e}"))?;
            let s = std::str::from_utf8(&plaintext).map_err(|_| anyhow!("override utf8"))?;
            let v: Value = serde_json::from_str(s).map_err(|e| anyhow!("override json: {e}"))?;
            Some((o.priority, v))
        }
        None => None,
    };
    if let Some((_, ref patch)) = override_priority {
        merge_patch(&mut merged, patch);
    }

    // 6. Build the descriptor list for the agent.
    let bundles: Vec<DesiredBundle> = group_bundles
        .into_iter()
        .map(|(b, priority)| DesiredBundle {
            id: b.id,
            name: b.name,
            version: b.version,
            sha256: b.sha256,
            signature: b.signature,
            priority,
        })
        .collect();

    // 7. Hash. The state_hash covers (sorted bundle list digest) + (canonicalized merged config).
    //    Either changing requires a fresh sync.
    let mut hasher = Sha256::new();
    hasher.update(canonical_string(&merged).as_bytes());
    for b in &bundles {
        hasher.update(b"|");
        hasher.update(b.id.as_bytes());
        hasher.update(b"|");
        hasher.update(b.sha256.as_bytes());
        hasher.update(b"|");
        hasher.update(b.priority.to_le_bytes());
    }
    let digest = hasher.finalize();
    let state_hash = digest.iter().map(|b| format!("{b:02x}")).collect();

    Ok(DesiredState {
        state_hash,
        merged_config: merged,
        bundles,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ds(hash: &str) -> DesiredState {
        DesiredState {
            state_hash: hash.into(),
            merged_config: Value::Object(serde_json::Map::new()),
            bundles: Vec::new(),
        }
    }

    #[test]
    fn a_bumped_config_version_invalidates_the_entry() {
        let c = DesiredStateCache::new();
        c.put(1, "host-a", 7, &ds("aaa"));

        assert_eq!(c.get(1, "host-a", 7).unwrap().state_hash, "aaa");
        assert!(
            c.get(1, "host-a", 8).is_none(),
            "a config change must not be served from cache"
        );

        // ...and the entry is replaced, not duplicated, when recomputed at the new version.
        c.put(1, "host-a", 8, &ds("bbb"));
        assert_eq!(
            c.len(),
            1,
            "one entry per host, regardless of version churn"
        );
        assert_eq!(c.get(1, "host-a", 8).unwrap().state_hash, "bbb");
    }

    #[test]
    fn tenants_never_share_an_entry() {
        let c = DesiredStateCache::new();
        // Same host id under two tenants is not reachable in practice, but the key must
        // still keep them apart — this is the cross-tenant isolation rule applied to cache.
        c.put(1, "host-a", 1, &ds("tenant-one"));
        c.put(2, "host-a", 1, &ds("tenant-two"));

        assert_eq!(c.get(1, "host-a", 1).unwrap().state_hash, "tenant-one");
        assert_eq!(c.get(2, "host-a", 1).unwrap().state_hash, "tenant-two");
    }

    #[test]
    fn invalidate_host_drops_only_that_host() {
        let c = DesiredStateCache::new();
        c.put(1, "host-a", 1, &ds("aaa"));
        c.put(1, "host-b", 1, &ds("bbb"));

        c.invalidate_host(1, "host-a");

        assert!(c.get(1, "host-a", 1).is_none());
        assert_eq!(c.get(1, "host-b", 1).unwrap().state_hash, "bbb");
    }

    #[test]
    fn stats_separate_hits_from_misses() {
        let c = DesiredStateCache::new();
        c.put(1, "host-a", 1, &ds("aaa"));

        c.get(1, "host-a", 1).unwrap(); // hit
        c.get(1, "host-a", 2); // miss — stale version
        c.get(1, "host-z", 1); // miss — unknown host

        assert_eq!(c.stats(), (1, 2));
    }
}
