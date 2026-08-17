use serde::{Deserialize, Serialize};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    pub id: String,
    pub tenant_id: i64,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub enrolled_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub current_state_hash: Option<String>,
    /// Deadline for the bootstrap token issued by "Add host". Cleared at enrollment, so a
    /// non-`None` value here always describes a host that has not enrolled yet.
    pub bootstrap_expires_at: Option<i64>,
    /// Last answer from the agent to "do you carry local configuration that outranks what we
    /// send you?" — `None` until one arrives, which is not the same as `Some(false)`: an
    /// agent that predates the field says nothing, and we must not read that as a denial.
    ///
    /// The agent reports only this fact, never the local configuration, so the server can say
    /// a host is partly self-managed without ever holding what that configuration contains.
    pub local_config_present: Option<bool>,
    pub created_at: i64,
}

/// What a host is actually doing, in one field.
///
/// Three questions decide whether a host is healthy — did it enroll, is it still calling
/// home, and is it running the configuration we want — and an operator scanning a list needs
/// the answer to all three without opening each row. So they collapse into one status with a
/// fixed precedence, worst-first: each state is a prerequisite for asking the next question,
/// and reporting the later answer while an earlier one is failing would be misleading. A
/// host that stopped calling home a week ago is not "in sync" just because the last hash it
/// reported still matches; it is offline, and what it is running is anyone's guess.
///
///   `NeverEnrolled` / `AwaitingEnrollment` → it has no configuration to be in sync with
///   `Lost` / `Offline`                     → we cannot know what it is running
///   `OutOfSync` / `InSync`                 → it is talking to us, and this is the answer
///
/// The distinction *within* the un-enrolled states matters too: "Add host" writes a row
/// immediately, whether or not anyone runs the install command, and once the bootstrap token
/// expires that row can never enroll — `mark_enrolled_if_pending` requires
/// `bootstrap_expires_at > now`, and no token can be re-issued for an existing row. One
/// "pending" state would hide the difference between a host mid-install and a dead row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    /// Created, install command not run yet, token still valid. Actionable — run it.
    AwaitingEnrollment,
    /// Created and never enrolled; the token has expired. This row is unusable: delete it
    /// and add the host again to get a fresh install command.
    NeverEnrolled,
    /// Enrolled, but nothing has been heard from it for several poll intervals. Whatever it
    /// is running, it is not picking up changes. Often a reboot, a maintenance window or a
    /// brief network problem — it may well come back on its own.
    Offline,
    /// Silent past the deployment's `HOST_LOST_AFTER_HOURS` (48h by default): beyond the
    /// point where waiting is a plan. Something has to have happened to it — the service
    /// stopped, the agent was uninstalled, a firewall rule changed, the machine was
    /// decommissioned and nobody deleted the row. Kept apart from `Offline` because the two
    /// call for different responses: one you wait out, the other you go and investigate.
    Lost,
    /// Enrolled and calling home, but the configuration it reports having applied is not the
    /// one we would serve it now. Normal for a minute after a configuration change or a
    /// fresh enrollment; persistent means it is failing to apply (check its errors).
    OutOfSync,
    /// Enrolled, calling home, running exactly what we want. The only state that needs no
    /// explanation.
    InSync,
}

impl HostStatus {
    /// True for the states that describe a host we are in contact with, or were. The others
    /// describe a row that never became a running agent.
    pub fn is_enrolled(&self) -> bool {
        matches!(
            self,
            Self::Offline | Self::Lost | Self::OutOfSync | Self::InSync
        )
    }

    /// True while nothing is being heard from the host.
    pub fn is_silent(&self) -> bool {
        matches!(self, Self::Offline | Self::Lost)
    }
}

/// How long a host may stay quiet before its silence means something, in the two sizes an
/// operator reacts to differently.
///
/// The offline grace is derived from the tenant's effective poll interval, because that is
/// what makes a missed poll meaningful: three of them mean one thing at 30 seconds and quite
/// another at an hour. The lost threshold is deployment configuration instead — see
/// [`StatusThresholds::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusThresholds {
    /// Silence past this reads `Offline`.
    pub offline_after_secs: i64,
    /// Silence past this reads `Lost`. Always at least `offline_after_secs`.
    pub lost_after_secs: i64,
}

/// Default silence after which a host reads [`HostStatus::Lost`]: two days.
///
/// Long enough that a machine off over a weekend, or a laptop shut in a bag, is not declared
/// dead on the Monday — and short enough that a decommissioned box does not sit in the list
/// looking healthy. Operators who run a tighter or looser fleet override it with
/// `HOST_LOST_AFTER_HOURS`.
pub const DEFAULT_LOST_AFTER_SECS: i64 = 48 * 3_600;

impl StatusThresholds {
    /// Build the thresholds for a tenant polling every `min_poll_interval_secs`, with
    /// `lost_after_secs` from the deployment's configuration.
    ///
    /// Offline after three missed polls, so a single dropped request — or the ±10% jitter
    /// agents apply — does not turn a fleet amber, with a five-minute floor: at the fast
    /// tiers three polls is 45 seconds and the list would flicker on any brief blip. The
    /// multiplier still earns its place at the other end, where a tenant whose
    /// `min_poll_interval_secs` is overridden upward gets proportional grace instead of
    /// being reported offline permanently.
    ///
    /// The lost threshold is a human one rather than a protocol one — "we have not heard
    /// from that machine since Tuesday" is the same statement whatever the poll cadence — so
    /// it is configured, not derived. It is floored at the offline grace regardless of what
    /// was configured, because the two inverting would report a host lost while it was still
    /// polling on schedule. Where the floor bites, `Offline` is never shown and silence goes
    /// straight to `Lost`: at a cadence that slow, anything less is not yet evidence.
    pub fn new(min_poll_interval_secs: u32, lost_after_secs: i64) -> Self {
        const MISSED_POLLS: i64 = 3;
        const OFFLINE_FLOOR_SECS: i64 = 300;

        let offline_after_secs =
            (i64::from(min_poll_interval_secs) * MISSED_POLLS).max(OFFLINE_FLOOR_SECS);
        Self {
            offline_after_secs,
            lost_after_secs: lost_after_secs.max(offline_after_secs),
        }
    }
}

impl Host {
    /// Classify this host at time `now` (unix seconds).
    ///
    /// `desired_state_hash` is what we would serve this host right now; pass `None` when
    /// there is no desired state to compare against, which is the case for every host that
    /// has not enrolled. Passing `None` for an enrolled host yields `OutOfSync` — the safe
    /// direction, since this must never claim a convergence it cannot demonstrate.
    pub fn status(
        &self,
        now: i64,
        thresholds: StatusThresholds,
        desired_state_hash: Option<&str>,
    ) -> HostStatus {
        match (self.enrolled_at, self.bootstrap_expires_at) {
            // Enrollment wins over a stale deadline: enrollment clears the field, but a row
            // that still carries one must not read as un-enrolled.
            (Some(_), _) => {}
            (None, Some(expires_at)) if expires_at > now => {
                return HostStatus::AwaitingEnrollment;
            }
            // Includes `(None, None)`: a row with no live token that never enrolled.
            (None, _) => return HostStatus::NeverEnrolled,
        }

        // Enrollment itself counts as contact, so a host that has enrolled but not yet made
        // its first poll is not immediately reported offline.
        let last_contact = self
            .last_seen_at
            .or(self.enrolled_at)
            .unwrap_or(self.created_at);
        let silent_for = now - last_contact;
        // Longest silence first: where the two thresholds coincide (a tenant polling less
        // often than every eight hours) the more serious answer is the one that survives.
        if silent_for > thresholds.lost_after_secs {
            return HostStatus::Lost;
        }
        if silent_for > thresholds.offline_after_secs {
            return HostStatus::Offline;
        }

        match (self.current_state_hash.as_deref(), desired_state_hash) {
            (Some(applied), Some(desired)) if applied == desired => HostStatus::InSync,
            // Includes a host that has never reported applying anything: it is enrolled and
            // talking, but it is not yet running what we asked for.
            _ => HostStatus::OutOfSync,
        }
    }
}

pub fn new_host_id() -> String {
    Ulid::new().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const GRACE: i64 = 300;
    const LOST: i64 = DEFAULT_LOST_AFTER_SECS;
    const THRESHOLDS: StatusThresholds = StatusThresholds {
        offline_after_secs: GRACE,
        lost_after_secs: LOST,
    };

    fn host(enrolled_at: Option<i64>, bootstrap_expires_at: Option<i64>) -> Host {
        Host {
            id: "01HXXX".into(),
            tenant_id: 1,
            hostname: None,
            os: None,
            enrolled_at,
            last_seen_at: None,
            current_state_hash: None,
            bootstrap_expires_at,
            local_config_present: None,
            created_at: 1_000,
        }
    }

    /// An enrolled host that polled `seconds_ago` and last applied `applied`.
    fn live(seconds_ago: i64, applied: Option<&str>) -> Host {
        Host {
            enrolled_at: Some(NOW - 500_000),
            last_seen_at: Some(NOW - seconds_ago),
            current_state_hash: applied.map(str::to_owned),
            ..host(Some(NOW - 500_000), None)
        }
    }

    fn status(h: &Host, desired: Option<&str>) -> HostStatus {
        h.status(NOW, THRESHOLDS, desired)
    }

    #[test]
    fn a_live_token_is_awaiting_enrollment() {
        assert_eq!(
            status(&host(None, Some(NOW + 1)), None),
            HostStatus::AwaitingEnrollment
        );
    }

    #[test]
    fn an_expired_token_never_enrolled() {
        // Exactly at the deadline is already too late: `mark_enrolled_if_pending` requires
        // `bootstrap_expires_at > now`, so the status must flip at the same instant.
        assert_eq!(
            status(&host(None, Some(NOW)), None),
            HostStatus::NeverEnrolled
        );
        assert_eq!(
            status(&host(None, Some(NOW - 1)), None),
            HostStatus::NeverEnrolled
        );
        assert_eq!(status(&host(None, None), None), HostStatus::NeverEnrolled);
    }

    /// Enrollment clears `bootstrap_expires_at`, but a host must not read as un-enrolled if
    /// a stale deadline is still on the row.
    #[test]
    fn enrollment_wins_over_a_stale_deadline() {
        let mut h = live(5, Some("abc"));
        h.bootstrap_expires_at = Some(1);
        assert_eq!(status(&h, Some("abc")), HostStatus::InSync);
    }

    #[test]
    fn a_reporting_host_is_in_sync_only_when_the_hashes_match() {
        assert_eq!(
            status(&live(5, Some("abc")), Some("abc")),
            HostStatus::InSync
        );
        assert_eq!(
            status(&live(5, Some("old")), Some("abc")),
            HostStatus::OutOfSync
        );
        // Enrolled, talking, but has never reported applying anything — which is exactly
        // "not running what we asked for".
        assert_eq!(status(&live(5, None), Some("abc")), HostStatus::OutOfSync);
    }

    /// Silence outranks the hash. The last thing this host told us still matches what we
    /// would serve, but it has not confirmed anything since.
    #[test]
    fn a_host_that_stopped_calling_is_offline_not_in_sync() {
        assert_eq!(
            status(&live(GRACE + 1, Some("abc")), Some("abc")),
            HostStatus::Offline
        );
        assert_eq!(
            status(&live(GRACE, Some("abc")), Some("abc")),
            HostStatus::InSync,
            "exactly at the grace boundary is still in contact"
        );
    }

    /// A blip and a machine that has been gone since last week are different problems: one
    /// you wait out, the other you go and look at.
    #[test]
    fn a_long_silence_is_lost_rather_than_offline() {
        assert_eq!(
            status(&live(LOST, Some("abc")), Some("abc")),
            HostStatus::Offline,
            "exactly at the threshold is still only offline"
        );
        assert_eq!(
            status(&live(LOST + 1, Some("abc")), Some("abc")),
            HostStatus::Lost
        );
        assert_eq!(
            status(&live(30 * LOST, Some("abc")), Some("abc")),
            HostStatus::Lost,
            "and it stays lost however long it has been"
        );
    }

    /// Silence is silence: what the host last applied cannot rescue it from either state.
    #[test]
    fn lost_outranks_every_sync_answer() {
        for applied in [Some("abc"), Some("stale"), None] {
            assert_eq!(
                status(&live(LOST + 1, applied), Some("abc")),
                HostStatus::Lost
            );
        }
    }

    /// A host that has enrolled but not yet polled has still been heard from — the
    /// enrollment was contact. Without this it would flash offline the moment it appears.
    #[test]
    fn enrollment_counts_as_contact_until_the_first_poll() {
        let mut h = live(0, None);
        h.last_seen_at = None;
        h.enrolled_at = Some(NOW - 5);
        assert_eq!(status(&h, Some("abc")), HostStatus::OutOfSync);

        h.enrolled_at = Some(NOW - GRACE - 1);
        assert_eq!(
            status(&h, Some("abc")),
            HostStatus::Offline,
            "an enrollment that was never followed by a poll goes quiet like any other"
        );
    }

    /// Fail safe: with no desired state to compare against we say out of sync, never in.
    #[test]
    fn an_unknown_desired_state_never_claims_convergence() {
        assert_eq!(status(&live(5, Some("abc")), None), HostStatus::OutOfSync);
    }

    #[test]
    fn offline_grace_has_a_floor_and_scales_with_slow_polling() {
        let offline =
            |interval| StatusThresholds::new(interval, DEFAULT_LOST_AFTER_SECS).offline_after_secs;
        // Every shipped tier polls fast enough that the floor decides.
        assert_eq!(offline(15), 300);
        assert_eq!(offline(60), 300);
        // A tenant with an overridden, much slower interval gets proportional grace.
        assert_eq!(offline(3600), 10_800);
    }

    /// The lost threshold is whatever the deployment configured, except where that would
    /// land inside the offline grace — the two must never invert, or a host would read lost
    /// while it was still polling on schedule.
    #[test]
    fn lost_is_configurable_but_never_earlier_than_offline() {
        assert_eq!(
            StatusThresholds::new(60, DEFAULT_LOST_AFTER_SECS).lost_after_secs,
            172_800,
            "two days by default"
        );
        assert_eq!(
            StatusThresholds::new(60, 4 * 3_600).lost_after_secs,
            14_400,
            "a tighter deployment is honoured"
        );

        // Whatever is configured, and however slowly the tenant polls, the order holds.
        for interval in [15, 60, 3600, 28_800, 100_000] {
            for configured in [1, 300, 14_400, DEFAULT_LOST_AFTER_SECS, 30 * 86_400] {
                let t = StatusThresholds::new(interval, configured);
                assert!(
                    t.lost_after_secs >= t.offline_after_secs,
                    "inverted at {interval}s poll / {configured}s lost"
                );
            }
        }

        // A tenant polling every 10h outlasts the default: the grace wins and the two
        // collapse, so silence reads lost rather than briefly claiming offline too early.
        let slow = StatusThresholds::new(36_000, DEFAULT_LOST_AFTER_SECS);
        assert_eq!(slow.offline_after_secs, 108_000);
        assert_eq!(slow.lost_after_secs, 172_800);
        let slower = StatusThresholds::new(72_000, DEFAULT_LOST_AFTER_SECS);
        assert_eq!(slower.lost_after_secs, slower.offline_after_secs);
    }

    #[test]
    fn only_the_live_states_count_as_enrolled() {
        assert!(HostStatus::InSync.is_enrolled());
        assert!(HostStatus::OutOfSync.is_enrolled());
        assert!(HostStatus::Offline.is_enrolled());
        assert!(HostStatus::Lost.is_enrolled());
        assert!(!HostStatus::AwaitingEnrollment.is_enrolled());
        assert!(!HostStatus::NeverEnrolled.is_enrolled());

        assert!(HostStatus::Offline.is_silent() && HostStatus::Lost.is_silent());
        assert!(!HostStatus::InSync.is_silent() && !HostStatus::OutOfSync.is_silent());
    }
}
