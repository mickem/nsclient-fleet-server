use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, AtomicU32, Ordering};
use std::sync::Arc;

use fleet_core::time::now_unix;
use governor::clock::DefaultClock;
use governor::state::{InMemoryState, NotKeyed};
use governor::{Quota, RateLimiter as Governor};

type DirectLimiter = Governor<NotKeyed, InMemoryState, DefaultClock>;
type KeyedLimiter<K> = Governor<K, governor::state::keyed::DefaultKeyedStateStore<K>, DefaultClock>;

#[derive(Clone)]
pub struct AuthRateLimits {
    inner: Arc<Inner>,
}

struct Inner {
    per_email_minute: KeyedLimiter<String>,
    per_email_hour: KeyedLimiter<String>,
    per_ip_minute: KeyedLimiter<IpAddr>,
    per_ip_hour: KeyedLimiter<IpAddr>,
    daily_budget: u32,
    daily_count: AtomicU32,
    daily_window_start: AtomicI64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDecision {
    Allow,
    EmailLimited,
    IpLimited,
    BudgetExceeded,
}

impl AuthRateLimits {
    pub fn new(daily_budget: u32) -> Self {
        let inner = Inner {
            per_email_minute: Governor::keyed(Quota::per_minute(NonZeroU32::new(1).unwrap())),
            per_email_hour: Governor::keyed(Quota::per_hour(NonZeroU32::new(5).unwrap())),
            per_ip_minute: Governor::keyed(Quota::per_minute(NonZeroU32::new(10).unwrap())),
            per_ip_hour: Governor::keyed(Quota::per_hour(NonZeroU32::new(60).unwrap())),
            daily_budget,
            daily_count: AtomicU32::new(0),
            daily_window_start: AtomicI64::new(now_unix()),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Decide whether a send-link attempt is allowed.
    /// On `Allow` the relevant counters are consumed (so callers should not consume on rejection).
    pub fn check(&self, email: &str, ip: IpAddr) -> RateDecision {
        if self
            .inner
            .per_email_minute
            .check_key(&email.to_owned())
            .is_err()
            || self
                .inner
                .per_email_hour
                .check_key(&email.to_owned())
                .is_err()
        {
            return RateDecision::EmailLimited;
        }
        if self.inner.per_ip_minute.check_key(&ip).is_err()
            || self.inner.per_ip_hour.check_key(&ip).is_err()
        {
            return RateDecision::IpLimited;
        }
        if !self.consume_daily_budget() {
            return RateDecision::BudgetExceeded;
        }
        RateDecision::Allow
    }

    fn consume_daily_budget(&self) -> bool {
        let now = now_unix();
        let window_start = self.inner.daily_window_start.load(Ordering::Relaxed);
        if now - window_start >= 86_400 {
            self.inner.daily_window_start.store(now, Ordering::Relaxed);
            self.inner.daily_count.store(0, Ordering::Relaxed);
        }
        let prev = self.inner.daily_count.fetch_add(1, Ordering::Relaxed);
        if prev >= self.inner.daily_budget {
            self.inner.daily_count.fetch_sub(1, Ordering::Relaxed);
            return false;
        }
        true
    }
}

#[allow(dead_code)] // Used by tests only.
pub fn _unused_direct_limiter() -> DirectLimiter {
    Governor::direct(Quota::per_second(NonZeroU32::new(1).unwrap()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_limit_triggers_after_first_send() {
        let rl = AuthRateLimits::new(1000);
        let ip: IpAddr = "10.0.0.1".parse().unwrap();
        assert_eq!(rl.check("a@b", ip), RateDecision::Allow);
        // Second send within the per-minute window for the same email should be limited
        assert_eq!(rl.check("a@b", ip), RateDecision::EmailLimited);
        // Different email is still OK (under per-IP minute cap of 10)
        assert_eq!(rl.check("c@d", ip), RateDecision::Allow);
    }

    #[test]
    fn ip_limit_triggers_after_threshold() {
        let rl = AuthRateLimits::new(1000);
        let ip: IpAddr = "10.0.0.2".parse().unwrap();
        for i in 0..10 {
            let email = format!("user{i}@example.com");
            assert_eq!(rl.check(&email, ip), RateDecision::Allow);
        }
        // 11th distinct email from same IP within the minute → IP-limited
        assert_eq!(rl.check("user10@example.com", ip), RateDecision::IpLimited);
    }

    #[test]
    fn daily_budget_blocks_after_exhaustion() {
        let rl = AuthRateLimits::new(2);
        let ip1: IpAddr = "10.0.0.3".parse().unwrap();
        let ip2: IpAddr = "10.0.0.4".parse().unwrap();
        assert_eq!(rl.check("a@b", ip1), RateDecision::Allow);
        assert_eq!(rl.check("c@d", ip2), RateDecision::Allow);
        assert_eq!(
            rl.check("e@f", "10.0.0.5".parse().unwrap()),
            RateDecision::BudgetExceeded
        );
    }
}
