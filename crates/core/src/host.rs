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
    pub created_at: i64,
}

/// Where a host sits in its lifecycle, as an operator needs to see it.
///
/// The distinction that matters is *within* the un-enrolled hosts: "Add host" writes a row
/// immediately, whether or not anyone ever runs the install command. Those rows accumulate,
/// and once the bootstrap token expires they can never enroll — `mark_enrolled_if_pending`
/// requires `bootstrap_expires_at > now`, and there is no way to re-issue a token for an
/// existing row. Showing both as one "pending" state hides that difference, so an operator
/// cannot tell a host that is mid-install from one that is dead and needs deleting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostStatus {
    /// Ran the install command: it holds a client certificate and can poll.
    Enrolled,
    /// Created, install command not run yet, token still valid. Actionable — run it.
    AwaitingEnrollment,
    /// Created and never enrolled; the token has expired. This row is unusable: delete it
    /// and add the host again to get a fresh install command.
    NeverEnrolled,
}

impl Host {
    /// Classify this host at time `now` (unix seconds).
    pub fn status(&self, now: i64) -> HostStatus {
        match (self.enrolled_at, self.bootstrap_expires_at) {
            (Some(_), _) => HostStatus::Enrolled,
            (None, Some(expires_at)) if expires_at > now => HostStatus::AwaitingEnrollment,
            // Includes `(None, None)`: a row with no live token that never enrolled.
            (None, _) => HostStatus::NeverEnrolled,
        }
    }
}

pub fn new_host_id() -> String {
    Ulid::new().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

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
            created_at: 1_000,
        }
    }

    #[test]
    fn enrolled_hosts_are_enrolled() {
        assert_eq!(host(Some(900), None).status(1_000), HostStatus::Enrolled);
    }

    #[test]
    fn a_live_token_is_awaiting_enrollment() {
        assert_eq!(
            host(None, Some(1_001)).status(1_000),
            HostStatus::AwaitingEnrollment
        );
    }

    #[test]
    fn an_expired_token_never_enrolled() {
        // Exactly at the deadline is already too late: `mark_enrolled_if_pending` requires
        // `bootstrap_expires_at > now`, so the status must flip at the same instant.
        assert_eq!(
            host(None, Some(1_000)).status(1_000),
            HostStatus::NeverEnrolled
        );
        assert_eq!(
            host(None, Some(999)).status(1_000),
            HostStatus::NeverEnrolled
        );
        assert_eq!(host(None, None).status(1_000), HostStatus::NeverEnrolled);
    }

    /// Enrollment clears `bootstrap_expires_at`, but a host must read as enrolled even if a
    /// stale deadline is still on the row.
    #[test]
    fn enrollment_wins_over_a_stale_deadline() {
        assert_eq!(host(Some(900), Some(1)).status(1_000), HostStatus::Enrolled);
    }
}
