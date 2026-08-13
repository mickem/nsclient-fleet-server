pub mod email;
pub mod handlers;
pub mod middleware;
pub mod rate_limit;
pub mod tokens;
pub mod turnstile;

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use fleet_core::user::Role;

pub const SESSION_COOKIE: &str = "fleet_session";

#[derive(Clone, Debug)]
pub struct AuthedUser {
    pub user_id: i64,
    pub tenant_id: i64,
    /// Resolved by `session_layer` on every request, so a role change (or a deletion) takes
    /// effect on the user's next request rather than at their next sign-in.
    pub role: Role,
    /// Cross-tenant privilege, re-read on every request for the same reason as `role`.
    /// Checked only by the `PlatformAdmin` extractor — nothing in the tenant-scoped routes
    /// consults it, so a platform admin has exactly their own role inside their own tenant.
    pub is_platform_admin: bool,
}

/// Uniform refusal for a request the session is authenticated for but not permitted to make.
///
/// `need` names the missing capability rather than the role that would grant it — there is
/// more than one role for most of them, and the UI shows this string verbatim.
pub fn forbidden(need: &str) -> Response {
    (
        StatusCode::FORBIDDEN,
        format!("your role does not allow this ({need})"),
    )
        .into_response()
}
