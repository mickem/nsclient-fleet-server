//! A same-origin check on mutating requests, on top of `SameSite=Lax`.
//!
//! Lax already withholds the session cookie from a cross-*site* request, and the JSON
//! routes are further covered by axum refusing a body without `Content-Type:
//! application/json` — which a form post cannot set. What that leaves is the multipart
//! bundle upload, and a sibling subdomain of the same registrable domain: `Lax` considers
//! `evil.example.com → app.example.com` same-site and sends the cookie.
//!
//! `Sec-Fetch-Site` is the browser's own answer to "where did this request come from", and
//! a page cannot set or forge it. Requests it labels `cross-site` or `same-site` are
//! refused; `same-origin` and `none` (a typed URL, a bookmark) are allowed.
//!
//! Two deliberate holes, both structural rather than oversights:
//!
//! - a request with no `Sec-Fetch-Site` at all is allowed. Non-browser clients — curl, the
//!   agent, a script — never send it, and CSRF is a browser problem. Every browser that
//!   can be made to forge a cross-site request also sends this header.
//! - a request carrying a bearer token is allowed. API keys are not ambient credentials:
//!   a cross-site page cannot make the browser attach one, so there is nothing to forge.

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

pub async fn layer(req: Request<Body>, next: Next) -> Response {
    // Safe methods are out of scope: they are not supposed to change anything, and the
    // magic-link GET in particular is a top-level navigation that has to keep working.
    let mutating = matches!(
        *req.method(),
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    );
    if !mutating {
        return next.run(req).await;
    }

    let has_bearer = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().starts_with("bearer "));
    if has_bearer {
        return next.run(req).await;
    }

    let site = req
        .headers()
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase());

    match site.as_deref() {
        None | Some("same-origin") | Some("none") => next.run(req).await,
        Some(other) => {
            tracing::info!(
                sec_fetch_site = other,
                path = %req.uri().path(),
                "refused a mutating request from another origin"
            );
            (
                StatusCode::FORBIDDEN,
                "this request did not come from this site",
            )
                .into_response()
        }
    }
}
