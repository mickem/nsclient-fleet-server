//! Compute a host's desired state by walking tags → groups → bundles → host override,
//! priority-ordered merge, hash. Phase 5 replaces the placeholder used in Phase 4.
//!
//! Results are memoized per host against the tenant's `config_version` (Phase 9). Every
//! input to the computation — tags, groups and their selectors, bundle assignments, bundle
//! rows, host overrides — is behind a mutation path that bumps that counter, so a stale
//! entry cannot outlive a change. See `DesiredStateCache`. The per-host inputs a host
//! writes itself (its reported tags and its facts document) invalidate that host's entry
//! instead.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::RwLock;

use anyhow::{anyhow, Result};
use fleet_core::merge::canonical_string;
use fleet_core::selector::Selector;
use fleet_core::time::now_unix;
use fleet_storage::{
    BundleAssignmentsRepo, GroupsRepo, HostOverridesRepo, HostTagsRepo, TenantRepo,
};
use serde_json::Value;

use crate::AppState;

#[derive(Debug, Clone)]
pub struct DesiredBundle {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub signature: String,
    pub priority: i64,
    /// `plain` or `enc-v1` — forwarded to agents so they know to decrypt before unpacking.
    pub format: String,
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
    /// `None`: a tombstone. The host was invalidated and nothing has been computed for it
    /// since; the entry is kept only to carry `generation`.
    state: Option<DesiredState>,
    /// Bumped by every [`DesiredStateCache::invalidate_host`]. A compute records it before
    /// reading its inputs and may only store its result if it has not moved — see
    /// [`CacheTicket`].
    generation: u64,
    /// Atomic so a cache hit only needs the read lock.
    last_used: AtomicI64,
}

/// What a compute saw of a host's entry before it read its inputs. Storing the result is
/// refused if the host was invalidated in between: that compute may have read the document
/// or tags the invalidation was about, and caching it would pin the stale membership under
/// a `config_version` that no longer moves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheTicket {
    /// Moved whenever the idle sweep drops entries, since the generations go with them.
    epoch: u64,
    generation: u64,
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
    epoch: AtomicU64,
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
            let state = e.state.as_ref()?;
            (e.config_version == config_version).then(|| {
                e.last_used.store(now_unix(), Ordering::Relaxed);
                state.clone()
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

    /// Take before reading any input of a compute; hand to [`Self::put_if_current`].
    fn ticket(&self, tenant_id: i64, host_id: &str) -> CacheTicket {
        let map = self.entries.read().expect("desired-state cache lock");
        CacheTicket {
            // Read under the lock that `put_if_current` takes to bump it, so the two agree.
            epoch: self.epoch.load(Ordering::Relaxed),
            generation: map
                .get(&(tenant_id, host_id.to_string()))
                .map_or(0, |e| e.generation),
        }
    }

    /// Store a computed state, unless the host was invalidated after `ticket` was taken.
    /// Returns whether it was stored.
    fn put_if_current(
        &self,
        tenant_id: i64,
        host_id: &str,
        ticket: CacheTicket,
        config_version: i64,
        state: &DesiredState,
    ) -> bool {
        let mut map = self.entries.write().expect("desired-state cache lock");
        let key = (tenant_id, host_id.to_string());
        let generation = map.get(&key).map_or(0, |e| e.generation);
        if ticket.epoch != self.epoch.load(Ordering::Relaxed) || ticket.generation != generation {
            return false;
        }
        if map.len() >= MAX_ENTRIES {
            let cutoff = now_unix() - IDLE_TTL_SECS;
            let before = map.len();
            map.retain(|_, e| e.last_used.load(Ordering::Relaxed) >= cutoff);
            if map.len() >= MAX_ENTRIES {
                // Nothing was idle. Rather than grow without bound, start over and pay the
                // recompute; this should never happen on a single-VM fleet.
                map.clear();
            }
            // Whatever went took its generation with it: a later invalidation of that host
            // would start again from 1 and could match a ticket taken before the sweep, and
            // the stale state that compute read would be stored. Moving the epoch voids every
            // ticket in flight instead, which costs at most one recompute each.
            if map.len() < before {
                self.epoch.fetch_add(1, Ordering::Relaxed);
            }
            tracing::info!(
                before,
                after = map.len(),
                "desired-state cache reclaimed entries"
            );
        }
        map.insert(
            key,
            Entry {
                config_version,
                state: Some(state.clone()),
                generation,
                last_used: AtomicI64::new(now_unix()),
            },
        );
        true
    }

    /// Store unconditionally, for tests that are not about the race.
    #[cfg(test)]
    fn put(&self, tenant_id: i64, host_id: &str, config_version: i64, state: &DesiredState) {
        let ticket = self.ticket(tenant_id, host_id);
        assert!(self.put_if_current(tenant_id, host_id, ticket, config_version, state));
    }

    /// Forget a host that is gone — deleted, or cut off pending re-enrollment — entirely.
    /// Not [`Self::invalidate_host`], whose tombstone would stay in the map for a host that
    /// never polls again: a fleet that enrolls and deletes hosts all day would fill the map
    /// with them.
    ///
    /// Dropping the entry drops its generation, as a sweep does, and for the same reason the
    /// epoch moves with it: a revoked host keeps its row, so an operator can still edit its
    /// tags, and that invalidation would start it again from generation 1 — possibly the
    /// generation of a compute still in flight, whose pre-edit result would then be stored
    /// and served once the host re-enrolls under the same id. Moving the epoch voids every
    /// ticket in flight, at the cost of one recompute each.
    pub fn forget_host(&self, tenant_id: i64, host_id: &str) {
        let mut map = self.entries.write().expect("desired-state cache lock");
        if map.remove(&(tenant_id, host_id.to_string())).is_some() {
            // Under the write lock, so no ticket is taken between the removal and the bump.
            self.epoch.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Drop a host's cached state because one of its own inputs — its reported tags or
    /// facts — changed, which `config_version` does not cover. A compute already under way
    /// for this host will not store its result. For a host that is going away, use
    /// [`Self::forget_host`].
    pub fn invalidate_host(&self, tenant_id: i64, host_id: &str) {
        let mut map = self.entries.write().expect("desired-state cache lock");
        let entry = map
            .entry((tenant_id, host_id.to_string()))
            .or_insert_with(|| Entry {
                config_version: 0,
                state: None,
                generation: 0,
                last_used: AtomicI64::new(now_unix()),
            });
        entry.state = None;
        entry.generation += 1;
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

    // Before reading anything the result depends on.
    let ticket = state.desired_state_cache.ticket(tenant_id, host_id);
    let computed = compute_uncached(state, tenant_id, host_id).await?;

    // Store against the version we were handed. If a bump landed while we were computing,
    // this entry is already stale-by-key and the next poll recomputes — the same outcome as
    // having no cache, never a stale answer. A bump to this host alone (its facts or tags)
    // is not in the version; the ticket catches that one.
    state
        .desired_state_cache
        .put_if_current(tenant_id, host_id, ticket, config_version, &computed);
    Ok(computed)
}

/// HKDF label for the `state_hash` MAC key. Changing it invalidates every stored hash,
/// which costs one extra sync per host and nothing else.
const STATE_HASH_INFO: &str = "desired-state-hash/v1";

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

    // 2. Find groups whose selector matches the host. Facts documents are loaded only for
    //    the sources some selector reads — none at all for a tenant grouping on tags alone.
    let groups = GroupsRepo::new(&state.db).list(tenant_id).await?;
    let selectors: Vec<(&str, Selector)> = groups
        .iter()
        .filter_map(|g| {
            let selector_v: Value = serde_json::from_str(&g.selector_json).ok()?;
            Some((g.id.as_str(), Selector::from_json(&selector_v).ok()?))
        })
        .collect();
    let sources: BTreeSet<String> = selectors
        .iter()
        .flat_map(|(_, s)| s.fact_sources())
        .collect();
    let facts = crate::facts::load_for_host(state, tenant_id, host_id, &sources).await?;
    let matching_group_ids: Vec<String> = selectors
        .iter()
        .filter(|(_, s)| s.matches(&tags, &facts))
        .map(|(id, _)| (*id).to_owned())
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
    //    The agent applies bundles itself once it downloads them, so the state_hash
    //    covers each bundle's full signed descriptor (see step 7), not the config inside.
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
                .decrypt(
                    fleet_core::aead::Purpose::HostOverride { tenant_id, host_id },
                    &o.patch_encrypted,
                )
                .map_err(|e| anyhow!("override decrypt: {e}"))?;
            let s = std::str::from_utf8(&plaintext).map_err(|_| anyhow!("override utf8"))?;
            let v: Value = serde_json::from_str(s).map_err(|e| anyhow!("override json: {e}"))?;
            Some((o.priority, v))
        }
        None => None,
    };
    // The override goes to the agent exactly as stored, nulls included: a null is a
    // removal ("delete this key on this host"), which only means something to the agent,
    // merging over the bundles. Merging it onto the empty document here would strip every
    // null and silently drop the removals. A non-object can only be a row from before PUT
    // validated the shape, and the agent refuses a document that is not an object.
    if let Some((_, patch)) = override_priority {
        if patch.is_object() {
            merged = patch;
        } else {
            tracing::warn!(%host_id, "ignoring a host override that is not a JSON object");
        }
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
            format: b.format,
        })
        .collect();

    // 7. The state_hash covers the canonicalized merged config and the sorted bundle list.
    //    Either changing requires a fresh sync.
    //
    //    Keyed, not a plain digest. The merged config contains the host override in
    //    plaintext, overrides are where credentials live, and this value is served to every
    //    role through the hosts API as well as to the agent. A bare SHA-256 of it is an
    //    offline guessing oracle: the bundle half is visible through the same endpoint, so
    //    anyone who can read the hash can try candidate passwords against it until one
    //    matches. Under HMAC with a key derived from MASTER_KEY the value still changes
    //    exactly when the content does, and tells a reader nothing about what is in it.
    //
    //    Each bundle contributes everything the agent is handed about it — the whole signed
    //    descriptor plus its priority — not just id and digest. A change to any of it is a
    //    change the agent has to see: a rename keeps id and bytes but changes the name and
    //    the signature, and an agent kept on 304 would hold a signature that no longer
    //    matches what we would serve. Every field is length-prefixed, so no value can shift
    //    bytes into its neighbour (names uploaded before validation can hold anything).
    let mut msg = Vec::new();
    let mut field = |bytes: &[u8]| {
        msg.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        msg.extend_from_slice(bytes);
    };
    field(canonical_string(&merged).as_bytes());
    for b in &bundles {
        field(b.id.as_bytes());
        field(b.name.as_bytes());
        field(b.version.as_bytes());
        field(b.format.as_bytes());
        field(b.sha256.as_bytes());
        field(b.signature.as_bytes());
        field(&b.priority.to_le_bytes());
    }
    let tag = state.config.master_key.mac(STATE_HASH_INFO, &msg);
    let state_hash = tag.iter().map(|b| format!("{b:02x}")).collect();

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
    fn a_compute_that_raced_an_invalidation_is_not_cached() {
        let c = DesiredStateCache::new();
        c.put(1, "host-a", 1, &ds("old"));
        c.invalidate_host(1, "host-a");

        // A compute starts, reading the host's facts...
        let ticket = c.ticket(1, "host-a");
        // ...a new document lands and invalidates the host...
        c.invalidate_host(1, "host-a");
        // ...and the compute finishes with what it read before.
        assert!(!c.put_if_current(1, "host-a", ticket, 1, &ds("stale")));
        assert!(c.get(1, "host-a", 1).is_none(), "the next poll recomputes");

        // A compute that started after the invalidation is stored.
        let ticket = c.ticket(1, "host-a");
        assert!(c.put_if_current(1, "host-a", ticket, 1, &ds("fresh")));
        assert_eq!(c.get(1, "host-a", 1).unwrap().state_hash, "fresh");
    }

    #[test]
    fn an_invalidation_of_an_uncached_host_still_stops_a_compute_in_flight() {
        let c = DesiredStateCache::new();
        let ticket = c.ticket(1, "host-a");
        c.invalidate_host(1, "host-a");
        assert!(!c.put_if_current(1, "host-a", ticket, 1, &ds("stale")));
    }

    #[test]
    fn a_sweep_that_drops_a_tombstone_voids_tickets_taken_before_it() {
        let c = DesiredStateCache::new();
        // host-a was invalidated long ago (generation 1), and a compute for it is running.
        c.invalidate_host(1, "host-a");
        let ticket = c.ticket(1, "host-a");
        c.entries.read().unwrap()[&(1, "host-a".to_string())]
            .last_used
            .store(now_unix() - IDLE_TTL_SECS - 1, Ordering::Relaxed);
        // The map fills up; the next store sweeps, and the idle tombstone goes.
        for i in 0..MAX_ENTRIES {
            c.put(1, &format!("filler-{i}"), 1, &ds("x"));
        }
        assert!(!c
            .entries
            .read()
            .unwrap()
            .contains_key(&(1, "host-a".to_string())));
        // A new invalidation starts host-a from generation 1 again — the ticket's own —
        // but the sweep moved the epoch, so the stale compute is still refused.
        c.invalidate_host(1, "host-a");
        assert!(!c.put_if_current(1, "host-a", ticket, 1, &ds("stale")));
    }

    #[test]
    fn a_forgotten_host_leaves_nothing_behind() {
        let c = DesiredStateCache::new();
        c.put(1, "host-a", 1, &ds("aaa"));
        c.invalidate_host(1, "host-a");
        c.forget_host(1, "host-a");
        c.forget_host(1, "never-cached");
        assert_eq!(c.len(), 0);
    }

    #[test]
    fn forgetting_a_host_voids_tickets_taken_before_it() {
        let c = DesiredStateCache::new();
        // host-a's tags were edited once (generation 1), and a compute for it is running.
        c.invalidate_host(1, "host-a");
        let ticket = c.ticket(1, "host-a");
        // The host is revoked; its entry, and with it its generation, goes.
        c.forget_host(1, "host-a");
        // An operator edits the revoked host's tags: it starts again from generation 1 —
        // the ticket's own — but forgetting moved the epoch, so the stale compute is refused.
        c.invalidate_host(1, "host-a");
        assert!(!c.put_if_current(1, "host-a", ticket, 1, &ds("stale")));
        assert!(c.get(1, "host-a", 1).is_none());

        // Forgetting a host that was never cached leaves other hosts' computes alone.
        let ticket = c.ticket(1, "host-b");
        c.forget_host(1, "never-cached");
        assert!(c.put_if_current(1, "host-b", ticket, 1, &ds("fresh")));
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
