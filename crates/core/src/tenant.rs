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
