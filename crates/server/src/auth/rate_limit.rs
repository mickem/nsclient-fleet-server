//! Rate limits for the unauthenticated auth endpoints.
//!
//! The per-email limiters are keyed on a caller-supplied string, which makes their memory
//! the attacker's to spend unless three things hold: the key has to be bounded in size,
//! the number of keys one caller can create has to be bounded, and keys have to go away.
//! All three are enforced here — see [`AuthRateLimits::check`].

use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicUsize, Ordering};
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
    /// Checks since the last prune. Pruning on a counter rather than a background task
    /// keeps the limiter a plain value with no lifecycle, which is what the tests and the
    /// several call sites that construct one all assume.
    since_prune: AtomicUsize,
}

/// Longest address we will key a limiter on. RFC 5321 caps a path at 254 octets, and
/// anything longer is not an address anyone is trying to sign in with.
const MAX_EMAIL_LEN: usize = 254;

/// Checks between prunes. Small enough that a flood cannot get far ahead of the sweep,
/// large enough that the sweep is not on the hot path of ordinary traffic.
const PRUNE_EVERY: usize = 512;

/// A cheap shape check, not an attempt at validating deliverability.
///
/// Its job is to keep junk out of the limiter's keyspace before a key is created from it,
/// so it rejects on length and on obviously-not-an-address rather than trying to be RFC
/// 5322. A real address that this rejects would also fail to receive the mail.
fn plausible_email(email: &str) -> bool {
    if email.is_empty() || email.len() > MAX_EMAIL_LEN {
        return false;
    }
    if email.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    let mut parts = email.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
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
            since_prune: AtomicUsize::new(0),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    /// Decide whether a send-link or signup attempt is allowed.
    /// On `Allow` the relevant counters are consumed (so callers should not consume on rejection).
    ///
    /// Order matters and is not the obvious one. The per-email limiters are keyed on a
    /// string the caller chose, so consulting them first meant every request with a fresh
    /// string inserted an entry — with no length cap on the key and nothing that ever
    /// removed one. A single address sending distinct strings grew the process until it was
    /// killed. So: reject implausible addresses before they can become a key, spend the
    /// caller's own per-IP budget first, and only then key anything on their input. One IP
    /// can now create at most sixty email keys an hour, and [`Self::prune`] removes them
    /// once they have replenished.
    pub fn check(&self, email: &str, ip: IpAddr) -> RateDecision {
        self.maybe_prune();

        if !plausible_email(email) {
            // Indistinguishable from a limited address to the caller, which is what the
            // send-link endpoint's uniform response wants anyway.
            return RateDecision::EmailLimited;
        }
        if self.inner.per_ip_minute.check_key(&ip).is_err()
            || self.inner.per_ip_hour.check_key(&ip).is_err()
        {
            return RateDecision::IpLimited;
        }
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
        if !self.consume_daily_budget() {
            return RateDecision::BudgetExceeded;
        }
        RateDecision::Allow
    }

    fn maybe_prune(&self) {
        if self.inner.since_prune.fetch_add(1, Ordering::Relaxed) + 1 >= PRUNE_EVERY {
            self.inner.since_prune.store(0, Ordering::Relaxed);
            self.prune();
        }
    }

    /// Drop keys whose quota has fully replenished — they are indistinguishable from keys
    /// we have never seen, so keeping them buys nothing.
    pub fn prune(&self) {
        self.inner.per_email_minute.retain_recent();
        self.inner.per_email_hour.retain_recent();
        self.inner.per_ip_minute.retain_recent();
        self.inner.per_ip_hour.retain_recent();
    }

    /// Keys currently held, for tests and for anyone wondering what this costs.
    pub fn tracked_keys(&self) -> usize {
        self.inner.per_email_minute.len()
            + self.inner.per_email_hour.len()
            + self.inner.per_ip_minute.len()
            + self.inner.per_ip_hour.len()
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
        assert_eq!(rl.check("a@b.com", ip), RateDecision::Allow);
        // Second send within the per-minute window for the same email should be limited
        assert_eq!(rl.check("a@b.com", ip), RateDecision::EmailLimited);
        // Different email is still OK (under per-IP minute cap of 10)
        assert_eq!(rl.check("c@d.com", ip), RateDecision::Allow);
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
    fn implausible_addresses_never_become_keys() {
        let rl = AuthRateLimits::new(1000);
        let ip: IpAddr = "10.0.1.1".parse().unwrap();
        let long = format!("{}@example.com", "a".repeat(300));
        for bad in [
            "",
            "no-at-sign",
            "@example.com",
            "a@b",
            "a b@example.com",
            &long,
        ] {
            assert_eq!(rl.check(bad, ip), RateDecision::EmailLimited, "{bad:?}");
        }
        assert_eq!(
            rl.tracked_keys(),
            0,
            "a rejected address must not have allocated anything"
        );
    }

    #[test]
    fn one_ip_cannot_grow_the_keyspace_past_its_own_quota() {
        // The finding: the email limiters were consulted first, so every request with a
        // fresh string inserted an entry before the IP limiter ever got to say no.
        let rl = AuthRateLimits::new(1_000_000);
        let ip: IpAddr = "10.0.2.1".parse().unwrap();
        for i in 0..5_000 {
            rl.check(&format!("u{i}@example.com"), ip);
        }
        // Ten per minute and sixty per hour get through; the rest are refused before their
        // address is used as a key. Two email maps plus one entry in each IP map.
        assert!(
            rl.tracked_keys() <= 60 * 2 + 2,
            "keyspace grew to {} entries",
            rl.tracked_keys()
        );
    }

    #[test]
    fn pruning_releases_keys_that_have_replenished() {
        let rl = AuthRateLimits::new(1000);
        for i in 0..20 {
            let ip: IpAddr = format!("10.1.{}.{}", i / 256, i % 256).parse().unwrap();
            assert_eq!(
                rl.check(&format!("p{i}@example.com"), ip),
                RateDecision::Allow
            );
        }
        assert!(rl.tracked_keys() > 0);
        // Nothing has replenished yet, so a prune now is a no-op rather than a reset —
        // pruning must not be a way to clear the limits.
        rl.prune();
        assert!(rl.tracked_keys() > 0, "prune must not drop live state");
    }

    #[test]
    fn daily_budget_blocks_after_exhaustion() {
        let rl = AuthRateLimits::new(2);
        let ip1: IpAddr = "10.0.0.3".parse().unwrap();
        let ip2: IpAddr = "10.0.0.4".parse().unwrap();
        assert_eq!(rl.check("a@b.com", ip1), RateDecision::Allow);
        assert_eq!(rl.check("c@d.com", ip2), RateDecision::Allow);
        assert_eq!(
            rl.check("e@f.com", "10.0.0.5".parse().unwrap()),
            RateDecision::BudgetExceeded
        );
    }
}
