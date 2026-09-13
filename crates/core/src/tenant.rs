use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tenant {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub tier: String,
    /// Optional JSON object overlaying selected `TierLimits` fields on top of the base tier.
    /// `None` = use the named tier unchanged. See `fleet_core::tier::effective`.
    pub tier_overrides_json: Option<String>,
    pub trial_expires_at: Option<i64>,
    pub config_version: i64,
    pub created_at: i64,
}

/// Slug rules, applied everywhere a slug is accepted.
///
/// The slug reaches a certificate subject DN (`fleet_enrollment::generate_tenant_ca`) and
/// operator-facing URLs, so it is restricted to what is safe in both. This used to live in
/// the platform console with a comment saying it was not applied at signup, which is how a
/// self-service tenant could be named `ac me` and land on the same CA subject as an
/// existing `acme`.
pub fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// The refusal text, shared so both callers say the same thing.
pub const SLUG_RULE: &str =
    "slug must be 1-63 characters of a-z, 0-9 and dashes, not starting or ending with a dash";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rules() {
        assert!(valid_slug("acme"));
        assert!(valid_slug("acme-corp-2"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("-acme"));
        assert!(!valid_slug("acme-"));
        assert!(!valid_slug("Acme"), "uppercase is not allowed");
        assert!(!valid_slug("acme corp"), "spaces reach a certificate DN");
        assert!(!valid_slug("acme.corp"));
        assert!(!valid_slug(&"a".repeat(64)));
    }
}
