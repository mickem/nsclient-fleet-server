pub mod email;
pub mod handlers;
pub mod middleware;
pub mod rate_limit;
pub mod tokens;
pub mod turnstile;

pub const SESSION_COOKIE: &str = "fleet_session";

#[derive(Clone, Debug)]
pub struct AuthedUser {
    pub user_id: i64,
    pub tenant_id: i64,
}
