use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use fleet_storage::{ApiKeyRepo, SessionRepo, UserRepo};

use super::{tokens::hash_token, AuthedUser, SESSION_COOKIE};
use crate::AppState;

/// Reads the session cookie and, if valid, attaches `AuthedUser` to the request extensions.
/// Does not reject — let the route's `AuthedUser` extractor decide whether auth is required.
///
/// The user row is re-read on every request to pick up the current role. That costs one
/// indexed lookup, and buys two things: a demotion takes effect immediately rather than at
/// the victim's convenience, and a session whose user has been deleted stops authenticating
/// even if a row somehow outlived `UserRepo::delete`.
pub async fn session_layer(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let identified = match jar.get(SESSION_COOKIE) {
        Some(cookie) => from_session(&state, cookie.value()).await,
        None => match bearer_token(&req) {
            Some(token) => from_api_key(&state, &token).await,
            None => None,
        },
    };
    if let Some(who) = identified {
        req.extensions_mut().insert(who);
    }
    next.run(req).await
}

async fn from_session(state: &AppState, cookie_value: &str) -> Option<AuthedUser> {
    let session = SessionRepo::new(&state.db)
        .touch(&hash_token(cookie_value))
        .await
        .ok()??;
    let user = UserRepo::new(&state.db)
        .get(session.tenant_id, session.user_id)
        .await
        .ok()??;
    Some(AuthedUser {
        user_id: session.user_id,
        tenant_id: session.tenant_id,
        role: user.role,
    })
}

/// Authenticate `Authorization: Bearer nsk_…`.
///
/// A key carries its owner's current role, read here rather than stored with the key, so
/// re-roling or deleting the user immediately changes what their automation can do.
async fn from_api_key(state: &AppState, token: &str) -> Option<AuthedUser> {
    let keys = ApiKeyRepo::new(&state.db);
    let key = keys.find_by_hash(&hash_token(token)).await.ok()??;
    let user = UserRepo::new(&state.db)
        .get(key.tenant_id, key.user_id)
        .await
        .ok()??;

    // Best-effort: a failed write here must not cost the caller their request.
    if let Err(e) = keys.touch_last_used(&key.id).await {
        tracing::warn!(error = %e, key_id = %key.id, "api key last_used update failed");
    }

    Some(AuthedUser {
        user_id: key.user_id,
        tenant_id: key.tenant_id,
        role: user.role,
    })
}

/// Pull a bearer token out of the Authorization header. The scheme is matched
/// case-insensitively, as RFC 7235 requires.
fn bearer_token(req: &Request<Body>) -> Option<String> {
    let raw = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let (scheme, value) = raw.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for AuthedUser
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<AuthedUser>()
            .cloned()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "not signed in").into_response())
    }
}
