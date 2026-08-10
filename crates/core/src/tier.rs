/// Tier definitions live in code (the tenants row stores only the tier name string).
///
/// Deliberately not a database table: limits change rarely, a redeploy is an acceptable way
/// to change them, and code-defined limits are type-safe (`tier.max_hosts`) and grep-able.
/// Lookup is a scan of a fixed-size array at request time, which is free at this scale.
#[derive(Debug, Clone, Copy)]
pub struct TierLimits {
    pub name: &'static str,
    pub max_hosts: u32,
    pub min_poll_interval_secs: u32,
    pub per_host_requests_per_minute: u32,
    pub max_bundle_mb: u32,
}

/// Numeric subset of `TierLimits` that may be overridden per tenant. Anything not present
/// here is locked to the named tier — overrides cannot rename a tenant's tier.
#[derive(Debug, Default, Clone, Copy, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TierOverrides {
    pub max_hosts: Option<u32>,
    pub min_poll_interval_secs: Option<u32>,
    pub per_host_requests_per_minute: Option<u32>,
    pub max_bundle_mb: Option<u32>,
}

impl TierOverrides {
    pub fn from_json(s: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(s)
    }

    fn apply_to(self, base: TierLimits) -> TierLimits {
        TierLimits {
            name: base.name,
            max_hosts: self.max_hosts.unwrap_or(base.max_hosts),
            min_poll_interval_secs: self
                .min_poll_interval_secs
                .unwrap_or(base.min_poll_interval_secs),
            per_host_requests_per_minute: self
                .per_host_requests_per_minute
                .unwrap_or(base.per_host_requests_per_minute),
            max_bundle_mb: self.max_bundle_mb.unwrap_or(base.max_bundle_mb),
        }
    }
}

pub const FREE: TierLimits = TierLimits {
    name: "free",
    max_hosts: 5,
    min_poll_interval_secs: 60,
    per_host_requests_per_minute: 10,
    max_bundle_mb: 10,
};
pub const STARTER: TierLimits = TierLimits {
    name: "starter",
    max_hosts: 50,
    min_poll_interval_secs: 30,
    per_host_requests_per_minute: 30,
    max_bundle_mb: 50,
};
pub const PRO: TierLimits = TierLimits {
    name: "pro",
    max_hosts: 500,
    min_poll_interval_secs: 30,
    per_host_requests_per_minute: 60,
    max_bundle_mb: 100,
};
pub const ENTERPRISE: TierLimits = TierLimits {
    name: "enterprise",
    max_hosts: 5000,
    min_poll_interval_secs: 15,
    per_host_requests_per_minute: 120,
    max_bundle_mb: 250,
};
pub const ONPREM: TierLimits = TierLimits {
    name: "onprem",
    max_hosts: u32::MAX,
    min_poll_interval_secs: 15,
    per_host_requests_per_minute: 120,
    max_bundle_mb: 250,
};

pub const ALL: &[TierLimits] = &[FREE, STARTER, PRO, ENTERPRISE, ONPREM];

pub fn lookup(name: &str) -> Option<TierLimits> {
    ALL.iter().find(|t| t.name == name).copied()
}

pub fn lookup_or_free(name: &str) -> TierLimits {
    lookup(name).unwrap_or(FREE)
}

/// Effective tier limits for a tenant: base tier looked up by name, then the optional
/// override JSON applied on top. Invalid override JSON falls back to the unmodified base
/// (logged so operators notice — we don't want a typo to silently grant capacity).
pub fn effective(tier_name: &str, overrides_json: Option<&str>) -> TierLimits {
    let base = lookup_or_free(tier_name);
    let Some(raw) = overrides_json else {
        return base;
    };
    match TierOverrides::from_json(raw) {
        Ok(ov) => ov.apply_to(base),
        Err(e) => {
            tracing::error!(error = %e, tier = tier_name, "invalid tier_overrides_json; ignoring");
            base
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_known_tiers() {
        assert_eq!(lookup("free").map(|t| t.max_hosts), Some(5));
        assert_eq!(lookup("enterprise").map(|t| t.max_hosts), Some(5000));
        assert_eq!(lookup("onprem").map(|t| t.max_hosts), Some(u32::MAX));
        assert!(lookup("bogus").is_none());
    }
}
