//! The periodic sweep of rows that can no longer do anything.
//!
//! Both cleanups existed and neither was ever called, so `sessions` and `magic_links` only
//! grew. Nothing about that is a correctness problem — `SessionRepo::touch` and
//! `MagicLinkRepo::redeem` both refuse an expired row — but an expired session row is a
//! stored credential hash with no purpose, and a database that only grows eventually
//! becomes an operational one.

use std::time::Duration;

use fleet_storage::{Db, MagicLinkRepo, SessionRepo};

/// Between sweeps. Nothing depends on the timing, so this is the interval at which the cost
/// is invisible rather than one tuned to anything.
const INTERVAL: Duration = Duration::from_secs(3_600);

/// Run the sweep forever. Spawned once at startup.
pub async fn run(db: Db, session_idle_ttl_secs: i64) {
    loop {
        sweep(&db, session_idle_ttl_secs).await;
        tokio::time::sleep(INTERVAL).await;
    }
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
