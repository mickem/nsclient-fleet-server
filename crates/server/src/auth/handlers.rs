use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    Form, Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fleet_core::time::now_unix;
use fleet_storage::{MagicLinkRepo, SessionRepo, TenantRepo, UserRepo};
use serde::{Deserialize, Serialize};

use super::{
    rate_limit::RateDecision,
    tokens::{hash_token, random_token},
    AuthedUser, EXCHANGE_COOKIE, SESSION_COOKIE,
};
use crate::AppState;

const TRIAL_DAYS: i64 = 14;

#[derive(Deserialize)]
pub struct SignupBody {
    pub email: String,
    pub tenant_slug: String,
    pub tenant_name: String,
    #[serde(default)]
    pub turnstile_token: Option<String>,
}

#[derive(Deserialize)]
pub struct SendLinkBody {
    pub email: String,
}

#[derive(Deserialize)]
pub struct ExchangeQuery {
    pub t: String,
}

#[derive(Deserialize)]
pub struct OnPremLoginBody {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: i64,
    pub email: String,
    pub role: fleet_core::user::Role,
    pub tenant_id: i64,
    pub tenant_slug: String,
    pub tenant_name: String,
    pub on_prem: bool,
    pub trial_expires_at: Option<i64>,
    pub trial_expired: bool,
    /// Drives the Platform entry in the sidebar. The routes it leads to check the flag
    /// themselves — this only decides whether the UI offers the door.
    pub is_platform_admin: bool,
}

pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SignupBody>,
) -> Response {
    if state.config.on_prem {
        return (StatusCode::NOT_FOUND, "signup disabled in on-prem mode").into_response();
    }

    // Checked before Turnstile: when signups are closed nothing about this request matters,
    // and there is no reason to spend a siteverify round trip refusing it.
    match crate::platform::settings::signups_enabled(&state.db).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                "self-service signup is currently closed — contact your administrator for an invitation",
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "signup gate read failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "signup unavailable").into_response();
        }
    }

    let token = body.turnstile_token.as_deref().unwrap_or("");
    if !state.turnstile.verify(token, addr.ip()).await {
        return (StatusCode::FORBIDDEN, "turnstile failed").into_response();
    }

    let email = body.email.trim().to_lowercase();
    let slug = body.tenant_slug.trim().to_lowercase();
    if email.is_empty() || slug.is_empty() || body.tenant_name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, "missing field").into_response();
    }

    let tenants = TenantRepo::new(&state.db);
    let users = UserRepo::new(&state.db);

    if tenants.get_by_slug(&slug).await.unwrap_or(None).is_some() {
        return (StatusCode::CONFLICT, "slug taken").into_response();
    }
    if users.find_by_email(&email).await.unwrap_or(None).is_some() {
        return (StatusCode::CONFLICT, "email already registered").into_response();
    }

    let trial = now_unix() + TRIAL_DAYS * 86_400;
    let tenant = match tenants
        .create(&slug, body.tenant_name.trim(), "free", Some(trial))
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "tenant create failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    };

    if let Err(e) = crate::tenant_setup::ensure_secrets(&state, &tenant).await {
        tracing::error!(error = %e, tenant_id = tenant.id, "tenant secret generation failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
    }

    crate::audit::record(
        &state,
        tenant.id,
        None,
        "tenant.created",
        "tenant",
        &tenant.id.to_string(),
        Some(&serde_json::json!({ "slug": tenant.slug })),
    )
    .await;

    let user = match users
        .create(tenant.id, &email, fleet_core::user::Role::Owner)
        .await
    {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "user create failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    };

    // A fresh install where the operator set PLATFORM_ADMIN_EMAILS and then signed up: the
    // startup pass found no account for that address, so the grant happens here instead.
    crate::platform_admin_bootstrap(&state, &user).await;

    if let Err(e) = issue_and_send_link(&state, &user.email, tenant.id, user.id, addr).await {
        tracing::error!(error = %e, "magic link send failed");
    }

    StatusCode::NO_CONTENT.into_response()
}

pub async fn send_link(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SendLinkBody>,
) -> Response {
    if state.config.on_prem {
        return (
            StatusCode::NOT_FOUND,
            "magic-link login disabled in on-prem mode",
        )
            .into_response();
    }

    let email = body.email.trim().to_lowercase();
    if email.is_empty() {
        // Still return uniform 204 — never reveal validation state on this endpoint.
        return StatusCode::NO_CONTENT.into_response();
    }

    let decision = state.rate_limits.check(&email, addr.ip());
    match decision {
        RateDecision::Allow => {}
        RateDecision::EmailLimited | RateDecision::IpLimited => {
            tracing::info!(rate_limit = ?decision, %email, ip = %addr.ip(), "send-link rate-limited (silent)");
            return StatusCode::NO_CONTENT.into_response();
        }
        RateDecision::BudgetExceeded => {
            tracing::error!(target: "alert.send_budget", "global daily email budget exceeded — dropping send-link");
            return StatusCode::NO_CONTENT.into_response();
        }
    }

    // The lookup is one indexed read on every branch, so it costs the same for a known,
    // unknown or blocked address. The *delivery* is what differs — a DB insert plus an
    // awaited SMTP round-trip that only the known-and-unblocked case performs — so it runs on
    // a detached task rather than inline. Awaiting it here would make an active account's 204
    // measurably slower than the others, turning the deliberately uniform response into a
    // timing oracle for account enumeration.
    let users = UserRepo::new(&state.db);
    match users.find_by_email(&email).await {
        Ok(Some(user)) if !user.is_blocked() => {
            let state = state.clone();
            tokio::spawn(async move {
                if let Err(e) =
                    issue_and_send_link(&state, &user.email, user.tenant_id, user.id, addr).await
                {
                    tracing::error!(error = %e, "magic link send failed");
                }
            });
        }
        // A blocked account is treated exactly like an unknown one: no link, no send. Issuing
        // a link the session layer would refuse would only waste the budget and confirm the
        // address is real.
        Ok(Some(user)) => {
            tracing::info!(
                user_id = user.id,
                "send-link for a blocked account (uniform 204)"
            );
        }
        Ok(None) => tracing::debug!(%email, "send-link for unknown email (uniform 204)"),
        Err(e) => tracing::error!(error = %e, "send-link user lookup failed"),
    }

    StatusCode::NO_CONTENT.into_response()
}

/// Mint a single-use magic link and mail it. Shared with `crate::users::invite`, which is
/// the same operation for a user who has just been created.
pub(crate) async fn issue_and_send_link(
    state: &AppState,
    email: &str,
    tenant_id: i64,
    user_id: i64,
    _addr: SocketAddr,
) -> anyhow::Result<()> {
    let token = random_token();
    let hash = hash_token(&token);
    let expires_at = now_unix() + state.config.magic_link_ttl_secs;
    MagicLinkRepo::new(&state.db)
        .create(&hash, tenant_id, user_id, expires_at)
        .await?;

    let link = format!(
        "{}/api/auth/exchange?t={}",
        state.config.base_url.trim_end_matches('/'),
        token
    );
    state.email.send_magic_link(email, &link).await?;
    Ok(())
}

#[derive(Deserialize)]
pub struct ConfirmForm {
    /// The magic-link token, carried through from the emailed URL by the confirmation form.
    pub t: String,
    /// The double-submit nonce, echoed from the `fleet_exchange` cookie.
    pub csrf: String,
}

/// GET is the click target in the magic-link email. It deliberately does NOT sign anyone in:
/// a link click is a top-level GET that a cross-site page can trigger, so redeeming the token
/// and setting a session here would be login CSRF — an attacker who minted a link for their
/// own account could plant *their* session in a victim's browser and capture the victim's
/// work. Instead it renders a same-origin confirmation the user submits, and the token is
/// redeemed only on that POST (`exchange_confirm`).
///
/// A useful side effect: because GET has no side effect, link prefetchers (mail scanners,
/// antivirus, chat unfurlers) no longer burn a single-use token by merely following the URL.
pub async fn exchange(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<ExchangeQuery>,
) -> Response {
    let csrf = random_token();
    let mut cookie = Cookie::new(EXCHANGE_COOKIE, csrf.clone());
    cookie.set_http_only(true);
    // Strict: this cookie must only ever ride a same-origin submit of the page we just
    // rendered — never a cross-site request. Storing it works regardless of SameSite (the
    // link click is a top-level navigation), and the confirm POST is same-origin.
    cookie.set_same_site(SameSite::Strict);
    cookie.set_path("/");
    cookie.set_secure(state.config.cookie_secure);
    cookie.set_max_age(time::Duration::minutes(10));
    let jar = jar.add(cookie);

    let mut headers = HeaderMap::new();
    for c in jar.iter() {
        if let Ok(value) = HeaderValue::from_str(&c.to_string()) {
            headers.append(header::SET_COOKIE, value);
        }
    }
    (headers, Html(confirm_page_html(&q.t, &csrf))).into_response()
}

/// POST completes sign-in. It is reachable only by submitting the confirmation page, enforced
/// by a double-submit check: the `csrf` field must equal the `fleet_exchange` cookie value.
/// A cross-site caller can neither read that cookie's value (to fill the field) nor cause the
/// Strict cookie to be sent, so it cannot produce a matching pair — which is what stops the
/// login-CSRF the GET split avoids from simply moving to the POST.
pub async fn exchange_confirm(
    State(state): State<AppState>,
    jar: CookieJar,
    Form(form): Form<ConfirmForm>,
) -> Response {
    let matches = jar
        .get(EXCHANGE_COOKIE)
        .map(|c| constant_time_eq(c.value().as_bytes(), form.csrf.as_bytes()))
        .unwrap_or(false);
    if !matches {
        return (
            StatusCode::FORBIDDEN,
            "sign-in confirmation missing or expired — open the link again",
        )
            .into_response();
    }

    let hash = hash_token(&form.t);
    let (tenant_id, user_id) = match MagicLinkRepo::new(&state.db).redeem(&hash).await {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "invalid or expired link").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "redeem failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "redeem failed").into_response();
        }
    };

    // The one-time confirmation cookie has done its job; clear it so it cannot linger.
    let mut clear = Cookie::new(EXCHANGE_COOKIE, "");
    clear.set_path("/");
    let jar = jar.remove(clear);

    issue_session_cookie(&state, jar, tenant_id, user_id).await
}

/// The confirmation interstitial. Self-contained (the operator UI is a separate SPA bundle,
/// and this must render before any session exists).
///
/// `token` comes straight from the request URL and is therefore attacker-controlled, so both
/// interpolated values are HTML-attribute-escaped to keep this page free of reflected XSS.
fn confirm_page_html(token: &str, csrf: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in · NSClient Fleet</title>
<style>
  body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    background:#0d1117; color:#e6edf3; display:flex; min-height:100vh; margin:0;
    align-items:center; justify-content:center; }}
  main {{ background:#161b22; border:1px solid #30363d; border-radius:12px;
    padding:2.5rem; max-width:22rem; text-align:center; }}
  h1 {{ font-size:1.25rem; margin:0 0 .75rem; }}
  p {{ color:#8b949e; font-size:.9rem; line-height:1.5; margin:0 0 1.5rem; }}
  button {{ font:inherit; font-weight:600; color:#fff; background:#238636; border:0;
    border-radius:8px; padding:.7rem 1.5rem; width:100%; cursor:pointer; }}
  button:hover {{ background:#2ea043; }}
</style>
</head>
<body>
<main>
<h1>Sign in to NSClient Fleet</h1>
<p>Click below to finish signing in. If you didn't request this, just close this page.</p>
<form method="post" action="/api/auth/exchange">
<input type="hidden" name="t" value="{t}">
<input type="hidden" name="csrf" value="{c}">
<button type="submit">Sign in</button>
</form>
</main>
</body>
</html>"#,
        t = html_attr_escape(token),
        c = html_attr_escape(csrf),
    )
}

/// Escape a value for use inside a double-quoted HTML attribute.
fn html_attr_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(ch),
        }
    }
    out
}

pub async fn on_prem_login(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<OnPremLoginBody>,
) -> Response {
    if !state.config.on_prem {
        return (StatusCode::NOT_FOUND, "password login is on-prem only").into_response();
    }
    let admin_email = state.config.on_prem_admin_email.as_deref().unwrap_or("");
    let admin_pw = state.config.on_prem_admin_password.as_deref().unwrap_or("");
    if admin_email.is_empty() || admin_pw.is_empty() {
        return (StatusCode::SERVICE_UNAVAILABLE, "admin not configured").into_response();
    }

    let email_match = body.email.trim().eq_ignore_ascii_case(admin_email);
    let pw_match = constant_time_eq(body.password.as_bytes(), admin_pw.as_bytes());
    if !(email_match && pw_match) {
        return (StatusCode::UNAUTHORIZED, "bad credentials").into_response();
    }

    let users = UserRepo::new(&state.db);
    let user = match users.find_by_email(&admin_email.to_lowercase()).await {
        Ok(Some(u)) => u,
        _ => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "admin user missing").into_response();
        }
    };
    issue_session_cookie(&state, jar, user.tenant_id, user.id).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// The one place a session is minted — every sign-in path ends here, which is why the block
/// check lives here rather than in each of them. A link issued before the block was applied
/// is still a valid link; it just no longer buys a session.
async fn issue_session_cookie(
    state: &AppState,
    jar: CookieJar,
    tenant_id: i64,
    user_id: i64,
) -> Response {
    match UserRepo::new(&state.db).get(tenant_id, user_id).await {
        Ok(Some(u)) if u.is_blocked() => {
            tracing::info!(user_id, "sign-in refused: account blocked");
            return (StatusCode::FORBIDDEN, "this account has been blocked").into_response();
        }
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::UNAUTHORIZED, "no such account").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "sign-in user lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "sign-in failed").into_response();
        }
    }

    let token = random_token();
    let hash = hash_token(&token);
    if let Err(e) = SessionRepo::new(&state.db)
        .create(&hash, tenant_id, user_id, state.config.session_ttl_secs)
        .await
    {
        tracing::error!(error = %e, "session create failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "session create failed").into_response();
    }

    let mut cookie = Cookie::new(SESSION_COOKIE, token);
    cookie.set_http_only(true);
    cookie.set_same_site(SameSite::Lax);
    cookie.set_path("/");
    cookie.set_secure(state.config.cookie_secure);
    cookie.set_max_age(time_dur(state.config.session_ttl_secs));
    let jar = jar.add(cookie);

    let mut headers = HeaderMap::new();
    for c in jar.iter() {
        if let Ok(value) = HeaderValue::from_str(&c.to_string()) {
            headers.append(header::SET_COOKIE, value);
        }
    }
    (headers, Redirect::to("/")).into_response()
}

fn time_dur(secs: i64) -> time::Duration {
    time::Duration::seconds(secs)
}

pub async fn logout(State(state): State<AppState>, jar: CookieJar) -> Response {
    if let Some(c) = jar.get(SESSION_COOKIE) {
        let hash = hash_token(c.value());
        let _ = SessionRepo::new(&state.db).delete(&hash).await;
    }
    let mut clear = Cookie::new(SESSION_COOKIE, "");
    clear.set_path("/");
    clear.set_max_age(time::Duration::ZERO);
    let jar = jar.remove(clear);

    let mut headers = HeaderMap::new();
    for c in jar.iter() {
        if let Ok(value) = HeaderValue::from_str(&c.to_string()) {
            headers.append(header::SET_COOKIE, value);
        }
    }
    (headers, StatusCode::NO_CONTENT).into_response()
}

pub async fn me(State(state): State<AppState>, who: AuthedUser) -> Response {
    let users = UserRepo::new(&state.db);
    let tenants = TenantRepo::new(&state.db);
    let user = match users.get(who.tenant_id, who.user_id).await {
        Ok(Some(u)) => u,
        _ => return (StatusCode::UNAUTHORIZED, "stale session").into_response(),
    };
    let tenant = match tenants.get(who.tenant_id).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "tenant missing").into_response(),
    };
    let now = now_unix();
    let trial_expired = tenant
        .trial_expires_at
        .map(|exp| exp < now)
        .unwrap_or(false);
    Json(MeResponse {
        user_id: user.id,
        email: user.email,
        role: user.role,
        tenant_id: tenant.id,
        tenant_slug: tenant.slug,
        tenant_name: tenant.name,
        on_prem: state.config.on_prem,
        trial_expires_at: tenant.trial_expires_at,
        trial_expired,
        is_platform_admin: user.is_platform_admin,
    })
    .into_response()
}
