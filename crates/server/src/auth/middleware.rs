use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use axum_extra::extract::CookieJar;
use fleet_storage::SessionRepo;

use super::{tokens::hash_token, AuthedUser, SESSION_COOKIE};
use crate::AppState;

/// Reads the session cookie and, if valid, attaches `AuthedUser` to the request extensions.
/// Does not reject — let the route's `AuthedUser` extractor decide whether auth is required.
pub async fn session_layer(
    State(state): State<AppState>,
    jar: CookieJar,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    if let Some(cookie) = jar.get(SESSION_COOKIE) {
        let hash = hash_token(cookie.value());
        let sessions = SessionRepo::new(&state.db);
        if let Ok(Some(session)) = sessions.touch(&hash).await {
            req.extensions_mut().insert(AuthedUser {
                user_id: session.user_id,
                tenant_id: session.tenant_id,
            });
        }
    }
    next.run(req).await
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
