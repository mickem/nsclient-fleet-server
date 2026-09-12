//! Response headers that tell the browser what this origin is allowed to do.
//!
//! None of these were set. Without HSTS, a browser that once reached the plain-HTTP
//! address sends the session cookie in clear and keeps doing so; without a CSP, the
//! bundle key the client keeps in `sessionStorage` is one injected script away from
//! leaving the origin; without `nosniff`, a stored bundle can be re-interpreted as
//! whatever a sniffing browser decides it looks like.
//!
//! The values are built once at startup rather than per request, because they depend only
//! on configuration: whether we terminate TLS (HSTS), and whether Turnstile is on (which
//! third-party origin, if any, the policy has to admit). A deployment without Turnstile
//! gets the tighter policy, which is the right way round.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderName, HeaderValue, Request};
use axum::middleware::Next;
use axum::response::Response;

use crate::config::Config;

/// Precomputed headers, cloned per request as an `Arc` rather than rebuilt.
#[derive(Clone)]
pub struct SecurityHeaders {
    values: Arc<Vec<(HeaderName, HeaderValue)>>,
}

impl SecurityHeaders {
    pub fn from_config(cfg: &Config) -> Self {
        let mut values: Vec<(HeaderName, HeaderValue)> = Vec::new();

        // Only when we are the TLS terminator. Promising a browser that this origin is
        // HTTPS-only when it is served over plain HTTP locks the operator out of their own
        // dev server for a year, and a reverse proxy that terminates TLS is the one that
        // knows to send this.
        if cfg.terminates_tls() {
            values.push((
                header::STRICT_TRANSPORT_SECURITY,
                HeaderValue::from_static("max-age=31536000; includeSubDomains"),
            ));
        }

        values.push((
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ));
        values.push((header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY")));
        values.push((
            header::REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        ));
        // The magic link carries a single-use token in its query string. Nothing about this
        // origin should be reachable cross-origin anyway, but a stray token in a Referer is
        // exactly the sort of leak this header exists for.

        let csp = content_security_policy(cfg);
        if let Ok(v) = HeaderValue::from_str(&csp) {
            values.push((header::CONTENT_SECURITY_POLICY, v));
        } else {
            tracing::error!(%csp, "content security policy is not a valid header value");
        }

        Self {
            values: Arc::new(values),
        }
    }
}

/// The policy for the operator console.
///
/// `style-src` admits inline styles because MUI's emotion runtime injects `<style>` tags,
/// and so does the magic-link confirmation page. `script-src` does not: the SPA is a
/// bundled file served from this origin, and the only third party it ever loads is the
/// Turnstile widget — admitted only when Turnstile is actually configured.
fn content_security_policy(cfg: &Config) -> String {
    let mut script = String::from("'self'");
    let mut frame = String::from("'none'");
    if cfg.turnstile_site_key.is_some() {
        script.push_str(" https://challenges.cloudflare.com");
        frame = String::from("https://challenges.cloudflare.com");
    }
    [
        "default-src 'self'".to_string(),
        "base-uri 'self'".to_string(),
        // Belt and braces with X-Frame-Options, which older browsers understand instead.
        "frame-ancestors 'none'".to_string(),
        "form-action 'self'".to_string(),
        "object-src 'none'".to_string(),
        "img-src 'self' data:".to_string(),
        "font-src 'self' data:".to_string(),
        "style-src 'self' 'unsafe-inline'".to_string(),
        "connect-src 'self'".to_string(),
        format!("script-src {script}"),
        format!("frame-src {frame}"),
    ]
    .join("; ")
}

pub async fn layer(
    State(headers): State<SecurityHeaders>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let mut res = next.run(req).await;
    let h = res.headers_mut();
    for (name, value) in headers.values.iter() {
        // `insert`, not `append`: a handler that set one of these deliberately is not a
        // thing we have, and two conflicting CSPs are resolved by intersection, which is a
        // confusing way to end up with a policy nobody wrote.
        h.insert(name.clone(), value.clone());
    }
    res
}
