//! The periodic sweep of rows that can no longer do anything.
//!
//! Both cleanups existed and neither was ever called, so `sessions` and `magic_links` only
//! grew. Nothing about that is a correctness problem — `SessionRepo::touch` and
//! `MagicLinkRepo::redeem` both refuse an expired row — but an expired session row is a
//! stored credential hash with no purpose, and a database that only grows eventually
//! becomes an operational one.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use fleet_storage::{BundlesRepo, Db, MagicLinkRepo, SessionRepo};

use crate::bundles::BundleStore;

/// Between sweeps. Nothing depends on the timing, so this is the interval at which the cost
/// is invisible rather than one tuned to anything.
const INTERVAL: Duration = Duration::from_secs(3_600);

/// How old a bundle file no row points at must be before it is removed. Such files are
/// expected for a while: a re-seal staged for a rename that has not been committed yet, and
/// the ciphertext a rename replaced, which an agent may still be downloading.
pub const ORPHAN_BUNDLE_GRACE_SECS: i64 = 3_600;

/// Run the sweep forever. Spawned once at startup.
pub async fn run(db: Db, session_idle_ttl_secs: i64, store: Arc<dyn BundleStore>) {
    loop {
        sweep(&db, session_idle_ttl_secs).await;
        sweep_bundle_files(&db, store.as_ref(), ORPHAN_BUNDLE_GRACE_SECS).await;
        tokio::time::sleep(INTERVAL).await;
    }
}

/// Remove stored bundle files no row points at, once older than `grace_secs`: re-seals
/// staged for a rename that never happened, ciphertext a rename replaced, and whatever an
/// interrupted request left behind. Returns how many were removed.
///
/// A row is always written before its file is relied on, and a file without a row is never
/// served (downloads are authorized by row), so a file with no row is only ever waiting
/// for a commit or left over — the grace period is for the former.
pub async fn sweep_bundle_files(db: &Db, store: &dyn BundleStore, grace_secs: i64) -> usize {
    let files = match store.list().await {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(error = %e, "bundle file sweep: listing failed");
            return 0;
        }
    };
    // Read the rows after listing the files: a file written after the listing is not in
    // it, and a row written before the read is in the set.
    let rows: HashSet<(i64, String)> = match BundlesRepo::new(db).list_all().await {
        Ok(rows) => rows.into_iter().map(|b| (b.tenant_id, b.id)).collect(),
        Err(e) => {
            tracing::error!(error = %e, "bundle file sweep: row listing failed");
            return 0;
        }
    };
    let cutoff = fleet_core::time::now_unix() - grace_secs;
    let mut removed = 0;
    for f in files {
        if f.modified > cutoff || rows.contains(&(f.tenant_id, f.bundle_id.clone())) {
            continue;
        }
        match store.delete(f.tenant_id, &f.bundle_id).await {
            Ok(()) => removed += 1,
            Err(e) => {
                tracing::error!(error = %e, bundle_id = %f.bundle_id, "bundle file sweep: delete failed")
            }
        }
    }
    if removed > 0 {
        tracing::info!(removed, "swept bundle files no bundle points at");
    }
    removed
}

/// One pass. Errors are logged and the loop continues: housekeeping failing is not a reason
/// to stop housekeeping, and the next pass retries.
pub async fn sweep(db: &Db, session_idle_ttl_secs: i64) {
    match SessionRepo::new(db)
        .delete_expired(session_idle_ttl_secs)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "swept expired sessions"),
        Err(e) => tracing::error!(error = %e, "session sweep failed"),
    }
    match MagicLinkRepo::new(db).delete_expired().await {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "swept expired magic links"),
        Err(e) => tracing::error!(error = %e, "magic link sweep failed"),
    }
}
