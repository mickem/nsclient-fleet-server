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

/// The session cookie's name when we are not serving over TLS.
pub const SESSION_COOKIE: &str = "fleet_session";

/// The session cookie's name when we are.
///
/// `__Host-` is enforced by the browser, not by us: it refuses to store a cookie under this
/// name unless it is `Secure`, `Path=/`, and carries no `Domain`. The last of those is the
/// point — without it, anything that can write cookies for a sibling subdomain of the same
/// registrable domain can plant a session cookie on this origin, and the browser will send
/// it in preference to nothing. With it, that is not expressible.
pub const SESSION_COOKIE_SECURE: &str = "__Host-fleet_session";

/// Which of the two names this deployment uses. The name has to vary because `__Host-`
/// requires `Secure`, and a cookie that requires `Secure` cannot be stored at all over
/// plain HTTP — so a fixed prefixed name would break the no-TLS development path outright.
pub fn session_cookie_name(cookie_secure: bool) -> &'static str {
    if cookie_secure {
        SESSION_COOKIE_SECURE
    } else {
        SESSION_COOKIE
    }
}

/// Short-lived, HttpOnly, SameSite=Strict cookie set when the magic-link confirmation page is
/// rendered. Its value is echoed back in the confirmation form and compared server-side
/// (double-submit), so completing sign-in requires a same-origin submit of *our* page rather
/// than a cross-site request an attacker can forge. See `auth::handlers::exchange`.
pub const EXCHANGE_COOKIE: &str = "fleet_exchange";

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
