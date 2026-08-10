use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Instant;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use governor::clock::DefaultClock;
use governor::{Quota, RateLimiter as Governor};
use std::sync::Mutex;

use crate::mtls::PeerHostContext;
use crate::AppState;

type HostKey = (i64, String);
type HostKeyedLimiter =
    Governor<HostKey, governor::state::keyed::DefaultKeyedStateStore<HostKey>, DefaultClock>;

/// Per-host rate limits keyed `(tenant_id, host_id)`. One quota per tier (so changing tier
/// changes the effective quota for new entries; existing entries continue at their previous
/// quota until they age out — acceptable for v1).
#[derive(Clone)]
pub struct AgentRateLimits {
    inner: Arc<AgentRateLimitsInner>,
}

struct AgentRateLimitsInner {
    // Tier name → limiter. We size each limiter for that tier's per-host RPM.
    by_tier: std::sync::RwLock<HashMap<&'static str, Arc<HostKeyedLimiter>>>,
    last_poll: Mutex<HashMap<String, Instant>>,
}

impl AgentRateLimits {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(AgentRateLimitsInner {
                by_tier: std::sync::RwLock::new(HashMap::new()),
                last_poll: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn limiter_for_tier(&self, tier: &fleet_core::tier::TierLimits) -> Arc<HostKeyedLimiter> {
        if let Some(l) = self.inner.by_tier.read().expect("rl lock").get(&tier.name) {
            return l.clone();
        }
        let mut w = self.inner.by_tier.write().expect("rl lock");
        if let Some(l) = w.get(&tier.name) {
            return l.clone();
        }
        let qpm = NonZeroU32::new(tier.per_host_requests_per_minute.max(1)).unwrap();
        let limiter: Arc<HostKeyedLimiter> = Arc::new(Governor::keyed(Quota::per_minute(qpm)));
        w.insert(tier.name, limiter.clone());
        limiter
    }

    pub fn check_request(
        &self,
        tier: &fleet_core::tier::TierLimits,
        tenant_id: i64,
        host_id: &str,
    ) -> Result<(), u32> {
        let limiter = self.limiter_for_tier(tier);
        let key = (tenant_id, host_id.to_owned());
        match limiter.check_key(&key) {
            Ok(_) => Ok(()),
            Err(_negative) => {
                // Approximate retry-after: 60 / qpm seconds
                let retry = (60.0 / tier.per_host_requests_per_minute.max(1) as f64).ceil() as u32;
                Err(retry)
            }
        }
    }

    /// Returns Err(seconds_remaining) if a poll is too early per tier's min_poll_interval.
    pub fn check_poll_interval(
        &self,
        tier: &fleet_core::tier::TierLimits,
        host_id: &str,
    ) -> Result<(), u32> {
        let now = Instant::now();
        let mut g = self.inner.last_poll.lock().expect("poll map lock");
        if let Some(prev) = g.get(host_id) {
            let elapsed = now.duration_since(*prev).as_secs() as u32;
            if elapsed < tier.min_poll_interval_secs {
                return Err(tier.min_poll_interval_secs - elapsed);
            }
        }
        g.insert(host_id.to_owned(), now);
        Ok(())
    }

    /// Test-only: forget the last-poll time for a host. Lets integration tests exercise
    /// the 304 path without sleeping through a real poll interval.
    pub fn forget_last_poll(&self, host_id: &str) {
        self.inner
            .last_poll
            .lock()
            .expect("poll map lock")
            .remove(host_id);
    }

    /// Test-only: clear all per-tier limiters so retry loops in integration tests don't
    /// exhaust the per-host quota during a transient mTLS handshake failure (e.g., while
    /// the trust store is rebuilding after enrollment).
    pub fn clear_for_tests(&self) {
        self.inner.by_tier.write().expect("rl lock").clear();
    }
}

/// Per-tenant enrollment rate limiter. Applies to `/enroll/v1` after the bootstrap JWT is
/// validated, before signing a cert. Caps a tenant at ~10 enrollments per minute — well above
/// any realistic legitimate burst, well below what an attacker (or buggy script) could use to
/// fill the host table.
type TenantKeyedLimiter =
    Governor<i64, governor::state::keyed::DefaultKeyedStateStore<i64>, DefaultClock>;

#[derive(Clone)]
pub struct EnrollmentLimits {
    inner: Arc<TenantKeyedLimiter>,
    per_minute: u32,
}

impl EnrollmentLimits {
    pub fn new(per_minute: u32) -> Self {
        let qpm = NonZeroU32::new(per_minute.max(1)).unwrap();
        Self {
            inner: Arc::new(Governor::keyed(Quota::per_minute(qpm))),
            per_minute,
        }
    }

    /// Check whether the next enrollment for `tenant_id` is allowed. Returns Err(retry_secs) on rejection.
    pub fn check(&self, tenant_id: i64) -> Result<(), u32> {
        match self.inner.check_key(&tenant_id) {
            Ok(_) => Ok(()),
            Err(_) => Err((60.0 / self.per_minute as f64).ceil() as u32),
        }
    }
}

impl Default for EnrollmentLimits {
    fn default() -> Self {
        Self::new(10)
    }
}

impl Default for AgentRateLimits {
    fn default() -> Self {
        Self::new()
    }
}

/// Middleware applied to the mTLS router. Resolves tier, runs per-host rate limit, and (for
/// the desired-state route) the poll-interval floor.
pub async fn tier_layer(State(state): State<AppState>, req: Request<Body>, next: Next) -> Response {
    let ctx = match req.extensions().get::<PeerHostContext>() {
        Some(c) => c.clone(),
        None => {
            // Should be impossible if the mTLS pipeline is wired correctly; fail closed.
            return (StatusCode::INTERNAL_SERVER_ERROR, "no peer context").into_response();
        }
    };

    let tenant = match fleet_storage::TenantRepo::new(&state.db)
        .get(ctx.tenant_id)
        .await
    {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::FORBIDDEN, "tenant missing").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tier_layer tenant lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let tier = fleet_core::tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());

    if let Err(retry) = state
        .agent_limits
        .check_request(&tier, ctx.tenant_id, &ctx.host_id)
    {
        return rate_limited(retry);
    }

    if req.uri().path() == "/agent/v1/desired-state" {
        if let Err(retry) = state.agent_limits.check_poll_interval(&tier, &ctx.host_id) {
            return rate_limited(retry);
        }
    }

    next.run(req).await
}

fn rate_limited(retry_after_secs: u32) -> Response {
    let mut resp = (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    if let Ok(v) = HeaderValue::from_str(&retry_after_secs.to_string()) {
        resp.headers_mut().insert(header::RETRY_AFTER, v);
    }
    resp
}

#[cfg(test)]
mod enroll_tests {
    use super::*;

    #[test]
    fn limit_kicks_in_after_quota_exhausted() {
        let lim = EnrollmentLimits::new(3);
        // Burst of 3 should pass
        assert!(lim.check(7).is_ok());
        assert!(lim.check(7).is_ok());
        assert!(lim.check(7).is_ok());
        // 4th in same window — denied
        assert!(lim.check(7).is_err());
        // Different tenant unaffected
        assert!(lim.check(99).is_ok());
    }
}
