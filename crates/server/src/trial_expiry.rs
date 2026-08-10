//! Trial-expiry middleware. Tenants with `trial_expires_at < now` get 402 Payment Required
//! on every `/api/*` route except a small allowlist (logout, /api/me, healthz, frontend).

use axum::{
    body::Body,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::time::now_unix;
use fleet_storage::TenantRepo;

use crate::auth::AuthedUser;
use crate::AppState;

/// Paths that work even with an expired trial. The frontend uses /api/me to detect the
/// expired state and renders an "upgrade" view; logout lets the user sign out cleanly.
fn is_allowlisted(path: &str) -> bool {
    if !path.starts_with("/api/") {
        // /healthz, frontend assets, the /enroll/v1 endpoint (agents shouldn't be hit by
        // expiry — fleet operations don't suddenly fail when billing lapses).
        return true;
    }
    matches!(path, "/api/me" | "/api/auth/logout")
}

pub async fn trial_expiry_layer(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    if is_allowlisted(req.uri().path()) {
        return next.run(req).await;
    }
    // Only enforce when the request actually carries a session — anonymous routes
    // (auth/login, auth/signup) are unaffected.
    let who = match req.extensions().get::<AuthedUser>() {
        Some(u) => u.clone(),
        None => return next.run(req).await,
    };

    match TenantRepo::new(&state.db).get(who.tenant_id).await {
        Ok(Some(tenant)) => {
            if let Some(exp) = tenant.trial_expires_at {
                if exp < now_unix() {
                    return (
                        StatusCode::PAYMENT_REQUIRED,
                        Json(serde_json::json!({
                            "error": "trial_expired",
                            "trial_expires_at": exp,
                            "tenant_slug": tenant.slug,
                        })),
                    )
                        .into_response();
                }
            }
            next.run(req).await
        }
        Ok(None) => (StatusCode::FORBIDDEN, "tenant missing").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "trial_expiry tenant lookup failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}
