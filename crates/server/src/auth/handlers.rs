use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use fleet_core::time::now_unix;
use fleet_storage::{MagicLinkRepo, SessionRepo, TenantRepo, UserRepo};
use serde::{Deserialize, Serialize};

use super::{
    rate_limit::RateDecision,
    tokens::{hash_token, random_token},
    AuthedUser, SESSION_COOKIE,
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
}

pub async fn signup(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<SignupBody>,
) -> Response {
    if state.config.on_prem {
        return (StatusCode::NOT_FOUND, "signup disabled in on-prem mode").into_response();
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

    let users = UserRepo::new(&state.db);
    if let Ok(Some(user)) = users.find_by_email(&email).await {
        if let Err(e) =
            issue_and_send_link(&state, &user.email, user.tenant_id, user.id, addr).await
        {
            tracing::error!(error = %e, "magic link send failed");
        }
    } else {
        tracing::debug!(%email, "send-link for unknown email (uniform 204)");
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

pub async fn exchange(
    State(state): State<AppState>,
    jar: CookieJar,
    Query(q): Query<ExchangeQuery>,
) -> Response {
    let hash = hash_token(&q.t);
    let redeemed = MagicLinkRepo::new(&state.db).redeem(&hash).await;

    let (tenant_id, user_id) = match redeemed {
        Ok(Some(pair)) => pair,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "invalid or expired link").into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "redeem failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "redeem failed").into_response();
        }
    };

    issue_session_cookie(&state, jar, tenant_id, user_id).await
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

async fn issue_session_cookie(
    state: &AppState,
    jar: CookieJar,
    tenant_id: i64,
    user_id: i64,
) -> Response {
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
    })
    .into_response()
}
