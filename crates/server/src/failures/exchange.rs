//! Telling an agent we take failure reports.
//!
//! The agent posts nothing until a desired-state answer carries `X-Failure-Context: accept`,
//! and goes quiet again as soon as one does not. That makes this header the on/off switch
//! for the whole feature, reachable without touching a host — and it means the header has to
//! ride every answer, the `304` a host in sync gets on nearly every poll included.
//!
//! The optional `min-interval` parameter raises the agent's own reporting interval when ours
//! is longer. It is a *minimum*, not an instruction: an agent configured for a day keeps its
//! day. So this is a floor the server can raise to pace a large fleet, not a knob it can use
//! to ask for more traffic than the operator of the host allowed.

use axum::{
    http::{HeaderName, HeaderValue},
    response::Response,
};
use fleet_core::failures::{accept_header_value, FAILURE_CONTEXT_HEADER};
use fleet_storage::TenantFailureSettingsRepo;

use crate::AppState;

fn header_name() -> HeaderName {
    HeaderName::from_static(FAILURE_CONTEXT_HEADER)
}

/// The `X-Failure-Context` value for this tenant, or `None` to send no header.
///
/// `None` is the honest answer in two different situations, and the agent treats them the
/// same way — it posts nothing:
///
/// * the tenant has switched reports off, which is the point of the setting;
/// * the settings could not be read. Advertising on a failed lookup would invite a report we
///   might then refuse, and the agent reads a refusal as the report's own fault.
pub async fn advertise(state: &AppState, tenant_id: i64) -> Option<HeaderValue> {
    let settings = match TenantFailureSettingsRepo::new(&state.db)
        .get(tenant_id)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failure-report settings lookup failed");
            return None;
        }
    };
    // No row is the default, and the default is to take reports: a tenant that enrolled a
    // host has asked for its fleet to be managed, and a failed check is part of that. What
    // is off by default is sending any of it to a model (see `enrichment`).
    let (enabled, min_interval) = match settings {
        Some(s) => (s.reports_enabled, s.min_interval_secs),
        None => (true, 0),
    };
    if !enabled {
        return None;
    }
    let min_interval = min_interval.clamp(0, i64::from(u32::MAX)) as u32;
    HeaderValue::from_str(&accept_header_value(min_interval)).ok()
}

/// Attach the header to a response, if there is one to attach.
pub fn with_header(mut response: Response, value: Option<HeaderValue>) -> Response {
    if let Some(v) = value {
        response.headers_mut().insert(header_name(), v);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_header_name_is_the_one_the_agent_looks_up() {
        // The agent stores headers lower-cased and looks this up literally.
        assert_eq!(header_name().as_str(), "x-failure-context");
    }

    #[test]
    fn a_zero_minimum_sends_the_bare_accept() {
        // Which leaves the agent on its own configured interval — the default, and the one
        // that respects whoever configured the host.
        assert_eq!(accept_header_value(0), "accept");
        assert!(HeaderValue::from_str(&accept_header_value(0)).is_ok());
    }

    #[test]
    fn a_minimum_is_rendered_as_the_agent_parses_it() {
        let v = accept_header_value(7200);
        assert_eq!(v, "accept; min-interval=7200");
        assert!(
            HeaderValue::from_str(&v).is_ok(),
            "every value we build has to be a legal header"
        );
    }
}
