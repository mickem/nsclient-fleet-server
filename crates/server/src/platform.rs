//! The platform console: cross-tenant administration for whoever operates the service.
//!
//! Everything else in this server is tenant-scoped by construction — a handler takes
//! `who.tenant_id` from the session and every query carries it, so one tenant cannot read
//! another's rows even if a handler is wrong about permissions. These routes are the single
//! deliberate exception, and they are fenced off accordingly:
//!
//!   * one gate, `PlatformAdmin`, which every handler here takes as an argument. It is an
//!     extractor rather than an `if` so that forgetting the check is a compile error rather
//!     than a silent hole;
//!   * the flag it reads (`users.is_platform_admin`) is orthogonal to `Role` — being a
//!     platform admin grants nothing extra inside your own tenant, and being an owner grants
//!     nothing here;
//!   * these routes never touch fleet data. They cover subscriptions, user accounts, and the
//!     signup switch. Reading a tenant's hosts or configuration still requires being a user
//!     of that tenant, which is a boundary this console does not offer a way around.
//!
//! Audit entries for a platform action are written into the *target tenant's* log, attributed
//! to the platform admin's user id with their address in the metadata. A tenant is entitled
//! to see that its subscription changed and who changed it, and `audit_log.tenant_id` is
//! NOT NULL — so there is nowhere else for those entries to go.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, State},
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::tenant::Tenant;
use fleet_core::tier::{self, TierLimits, TierOverrides};
use fleet_core::time::now_unix;
use fleet_core::user::{Role, User};
use fleet_storage::{TenantRepo, TenantSummary, UserRepo};
use serde::{Deserialize, Serialize};

use crate::auth::{forbidden, AuthedUser};
use crate::AppState;

/// Process-wide switches, and what an unset one means.
pub mod settings {
    use anyhow::Result;
    use fleet_storage::{Db, PlatformSettingsRepo};

    /// Whether `POST /api/auth/signup` is open to the public.
    pub const SIGNUPS_ENABLED: &str = "signups_enabled";

    /// Signups are open unless someone has turned them off. A fresh database has no row, and
    /// defaulting to closed would mean a new install could not onboard its own first tenant.
    const SIGNUPS_ENABLED_DEFAULT: bool = true;

    pub async fn signups_enabled(db: &Db) -> Result<bool> {
        Ok(PlatformSettingsRepo::new(db)
            .get(SIGNUPS_ENABLED)
            .await?
            .map(|v| v == "true")
            .unwrap_or(SIGNUPS_ENABLED_DEFAULT))
    }

    pub async fn set_signups_enabled(db: &Db, enabled: bool, by_user: i64) -> Result<()> {
        PlatformSettingsRepo::new(db)
            .set(
                SIGNUPS_ENABLED,
                if enabled { "true" } else { "false" },
                Some(by_user),
            )
            .await
    }
}

/// Proof that the caller holds the platform-admin flag, carrying their identity.
///
/// Taking this as a handler argument *is* the authorization check — there is no `can_*`
/// method to call and no way to write a handler in this module that skips it.
pub struct PlatformAdmin(pub AuthedUser);

#[axum::async_trait]
impl<S> axum::extract::FromRequestParts<S> for PlatformAdmin
where
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, Self::Rejection> {
        let who = parts
            .extensions
            .get::<AuthedUser>()
            .cloned()
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, "not signed in").into_response())?;
        if !who.is_platform_admin {
            return Err(forbidden("platform administration"));
        }
        Ok(PlatformAdmin(who))
    }
}

// ---------------------------------------------------------------------------------------
// Wire types
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
pub struct TierLimitsView {
    pub name: String,
    pub max_hosts: u32,
    pub min_poll_interval_secs: u32,
    pub per_host_requests_per_minute: u32,
    pub max_bundle_mb: u32,
}

impl From<TierLimits> for TierLimitsView {
    fn from(t: TierLimits) -> Self {
        Self {
            name: t.name.to_string(),
            max_hosts: t.max_hosts,
            min_poll_interval_secs: t.min_poll_interval_secs,
            per_host_requests_per_minute: t.per_host_requests_per_minute,
            max_bundle_mb: t.max_bundle_mb,
        }
    }
}

#[derive(Serialize)]
pub struct TenantView {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub tier: String,
    /// The stored per-tenant overrides, or `None` when the tenant is on the unmodified tier.
    /// Absent fields inherit — this is what the console's "leave blank to inherit" means.
    pub overrides: Option<TierOverrides>,
    /// Tier plus overrides, i.e. the numbers this tenant is actually held to right now.
    pub effective: TierLimitsView,
    pub trial_expires_at: Option<i64>,
    pub trial_expired: bool,
    pub user_count: i64,
    pub blocked_user_count: i64,
    /// Hosts counted the way the `max_hosts` check counts them: enrolled, plus hosts still
    /// inside their 24h bootstrap window.
    pub host_count: i64,
    /// How many of those hosts report configuration of their own that outranks what the
    /// fleet sends them — the tenant-level view of what the host list shows per host.
    pub local_config_host_count: i64,
    pub created_at: i64,
}

impl From<TenantSummary> for TenantView {
    fn from(s: TenantSummary) -> Self {
        let t: Tenant = s.tenant;
        let effective = tier::effective(&t.tier, t.tier_overrides_json.as_deref());
        // A malformed override string is already logged (and ignored) by `tier::effective`;
        // the console shows `None` for it rather than inventing values it does not have.
        let overrides = t
            .tier_overrides_json
            .as_deref()
            .and_then(|raw| TierOverrides::from_json(raw).ok());
        TenantView {
            id: t.id,
            slug: t.slug,
            name: t.name,
            tier: t.tier,
            overrides,
            effective: effective.into(),
            trial_expired: t.trial_expires_at.map(|e| e < now_unix()).unwrap_or(false),
            trial_expires_at: t.trial_expires_at,
            user_count: s.user_count,
            blocked_user_count: s.blocked_user_count,
            host_count: s.host_count,
            local_config_host_count: s.local_config_host_count,
            created_at: t.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct PlatformUserView {
    pub id: i64,
    pub tenant_id: i64,
    pub email: String,
    pub role: Role,
    pub blocked_at: Option<i64>,
    pub is_platform_admin: bool,
    pub created_at: i64,
    /// True for the caller's own row. Every self-directed action here is refused — the UI
    /// uses this to disable controls rather than let them fail.
    pub is_self: bool,
}

fn user_view(u: User, caller: i64) -> PlatformUserView {
    PlatformUserView {
        is_self: u.id == caller,
        id: u.id,
        tenant_id: u.tenant_id,
        email: u.email,
        role: u.role,
        blocked_at: u.blocked_at,
        is_platform_admin: u.is_platform_admin,
        created_at: u.created_at,
    }
}

#[derive(Serialize)]
pub struct SettingsView {
    pub signups_enabled: bool,
    /// On-prem disables signup outright, regardless of the switch. Reported so the console
    /// can explain why the toggle is inert rather than looking broken.
    pub on_prem: bool,
}

/// What an anonymous visitor is allowed to know: whether the signup form is worth showing.
#[derive(Serialize)]
pub struct PublicConfigView {
    pub signups_enabled: bool,
    pub on_prem: bool,
}

// ---------------------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------------------

pub async fn list_tenants(State(state): State<AppState>, _: PlatformAdmin) -> Response {
    match TenantRepo::new(&state.db).list_with_counts().await {
        Ok(rows) => {
            Json(rows.into_iter().map(TenantView::from).collect::<Vec<_>>()).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "platform tenant list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "list failed").into_response()
        }
    }
}

/// The named tiers this build ships, so the console can show what a tier grants before it is
/// applied. Tiers live in code (`fleet_core::tier`), so this is the only way the UI can know
/// them without hardcoding a second copy that drifts.
pub async fn list_tiers(_: PlatformAdmin) -> Response {
    Json(
        tier::ALL
            .iter()
            .map(|t| TierLimitsView::from(*t))
            .collect::<Vec<_>>(),
    )
    .into_response()
}

#[derive(Deserialize)]
pub struct CreateTenantBody {
    pub slug: String,
    pub name: String,
    pub tier: String,
    /// Days from now until the trial ends. `None` creates the tenant with no trial deadline
    /// at all — the right shape for one that has already paid.
    #[serde(default)]
    pub trial_days: Option<i64>,
    /// Optional owner. Without one the tenant exists but nobody can sign into it, which is
    /// occasionally what you want (provisioning ahead of a sale) and usually is not.
    #[serde(default)]
    pub owner_email: Option<String>,
}

#[derive(Serialize)]
pub struct CreateTenantResponse {
    pub tenant: TenantView,
    /// False when no owner was requested, or when the account was created but the sign-in
    /// link could not be delivered. The tenant exists either way — see the handler.
    pub owner_invited: bool,
}

/// Slug rules, applied here and not at signup.
///
/// The slug reaches a certificate subject DN (`fleet_enrollment::generate_tenant_ca`) and
/// operator-facing URLs, so it is restricted to what is safe in both.
fn valid_slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

pub async fn create_tenant(
    State(state): State<AppState>,
    PlatformAdmin(who): PlatformAdmin,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<CreateTenantBody>,
) -> Response {
    let slug = body.slug.trim().to_lowercase();
    let name = body.name.trim();
    if !valid_slug(&slug) {
        return (
            StatusCode::BAD_REQUEST,
            "slug must be 1-63 characters of a-z, 0-9 and dashes, not starting or ending with a dash",
        )
            .into_response();
    }
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "name is required").into_response();
    }
    if tier::lookup(&body.tier).is_none() {
        return (StatusCode::BAD_REQUEST, "unknown tier").into_response();
    }
    let owner_email = match body.owner_email.as_deref().map(|e| e.trim().to_lowercase()) {
        Some(e) if e.is_empty() => None,
        Some(e) if !e.contains('@') => {
            return (StatusCode::BAD_REQUEST, "invalid owner email").into_response()
        }
        other => other,
    };

    let tenants = TenantRepo::new(&state.db);
    let users = UserRepo::new(&state.db);

    if tenants.get_by_slug(&slug).await.unwrap_or(None).is_some() {
        return (StatusCode::CONFLICT, "slug taken").into_response();
    }
    // Same rule as signup and invite, and for the same reason: sign-in resolves an address to
    // exactly one account, so an address may exist in exactly one tenant.
    if let Some(email) = owner_email.as_deref() {
        if users.find_by_email(email).await.unwrap_or(None).is_some() {
            return (StatusCode::CONFLICT, "email already registered").into_response();
        }
    }

    let trial_expires_at = body.trial_days.map(|d| now_unix() + d * 86_400);
    let tenant = match tenants
        .create(&slug, name, &body.tier, trial_expires_at)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "platform tenant create failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    };

    // Without a CA and a bundle-signing key the tenant cannot enrol a host, so this is part
    // of creating one, exactly as it is at signup.
    if let Err(e) = crate::tenant_setup::ensure_secrets(&state, &tenant).await {
        tracing::error!(error = %e, tenant_id = tenant.id, "tenant secret generation failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
    }

    crate::audit::record(
        &state,
        tenant.id,
        Some(who.user_id),
        "tenant.created",
        "tenant",
        &tenant.id.to_string(),
        Some(&serde_json::json!({
            "slug": tenant.slug,
            "tier": tenant.tier,
            "by": "platform",
            "actor": actor_email(&state, who.user_id).await,
        })),
    )
    .await;

    let mut owner_invited = false;
    let mut owner_created = false;
    if let Some(email) = owner_email {
        match users.create(tenant.id, &email, Role::Owner).await {
            Ok(user) => {
                owner_created = true;
                crate::platform_admin_bootstrap(&state, &user).await;
                match crate::auth::handlers::issue_and_send_link(
                    &state,
                    &user.email,
                    tenant.id,
                    user.id,
                    addr,
                )
                .await
                {
                    Ok(()) => owner_invited = true,
                    // Unlike `users::invite`, the account is kept: the tenant it owns has
                    // already been created and rolling the user back would leave a tenant
                    // nobody can reach. The response says the link did not go out, and the
                    // owner can request another from the sign-in form.
                    Err(e) => {
                        tracing::error!(error = %e, %email, "owner sign-in link could not be sent")
                    }
                }
                crate::audit::record(
                    &state,
                    tenant.id,
                    Some(who.user_id),
                    "user.invited",
                    "user",
                    &user.id.to_string(),
                    Some(&serde_json::json!({
                        "email": user.email, "role": user.role, "by": "platform",
                    })),
                )
                .await;
            }
            Err(e) => {
                tracing::error!(error = %e, "platform owner create failed");
            }
        }
    }

    (
        StatusCode::CREATED,
        Json(CreateTenantResponse {
            // Counts, rather than a second round trip to compute what is knowable here: a
            // brand-new tenant has no hosts and at most the one owner just created.
            tenant: TenantSummary {
                tenant,
                user_count: i64::from(owner_created),
                blocked_user_count: 0,
                host_count: 0,
                local_config_host_count: 0,
            }
            .into(),
            owner_invited,
        }),
    )
        .into_response()
}

#[derive(Deserialize)]
pub struct SubscriptionBody {
    pub tier: String,
    /// Unix seconds, or null for "no trial deadline" — i.e. a paying tenant.
    #[serde(default)]
    pub trial_expires_at: Option<i64>,
    /// Numeric overrides on top of the named tier. Null (or an object with every field
    /// null) puts the tenant back on the unmodified tier.
    #[serde(default)]
    pub overrides: Option<TierOverrides>,
}

/// Replace a tenant's subscription. The body is authoritative for all three fields — see
/// `TenantRepo::update_subscription` for why this is a PUT and not a PATCH.
pub async fn put_subscription(
    State(state): State<AppState>,
    PlatformAdmin(who): PlatformAdmin,
    Path(tenant_id): Path<i64>,
    Json(body): Json<SubscriptionBody>,
) -> Response {
    if tier::lookup(&body.tier).is_none() {
        return (StatusCode::BAD_REQUEST, "unknown tier").into_response();
    }

    let tenants = TenantRepo::new(&state.db);
    let before = match tenants.get(tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tenant lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
        }
    };

    // An override object whose every field is null is the same thing as no overrides. Storing
    // `{}` would work, but then "on the plain tier" would have two representations and the
    // console would have to render both identically.
    let overrides_json = match body.overrides {
        Some(ov) if !is_empty_overrides(&ov) => match serde_json::to_string(&ov) {
            Ok(s) => Some(s),
            Err(e) => {
                tracing::error!(error = %e, "override serialisation failed");
                return (StatusCode::BAD_REQUEST, "invalid overrides").into_response();
            }
        },
        _ => None,
    };

    match tenants
        .update_subscription(
            tenant_id,
            &body.tier,
            body.trial_expires_at,
            overrides_json.as_deref(),
        )
        .await
    {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "tenant not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "subscription update failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response();
        }
    }

    crate::audit::record(
        &state,
        tenant_id,
        Some(who.user_id),
        "tenant.subscription_changed",
        "tenant",
        &tenant_id.to_string(),
        Some(&serde_json::json!({
            "from": {
                "tier": before.tier,
                "trial_expires_at": before.trial_expires_at,
                "overrides": before.tier_overrides_json,
            },
            "to": {
                "tier": body.tier,
                "trial_expires_at": body.trial_expires_at,
                "overrides": overrides_json,
            },
            "by": "platform",
            "actor": actor_email(&state, who.user_id).await,
        })),
    )
    .await;

    // Nothing to invalidate: every limit is read from the tenant row at the point it is
    // enforced (`tier::effective` in hosts, bundles and agent_limits), so a new tier applies
    // to the next request. Only the per-tier rate-limiter buckets lag, and they age out.
    match tenants.get_with_counts(tenant_id).await {
        Ok(Some(s)) => Json(TenantView::from(s)).into_response(),
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

fn is_empty_overrides(ov: &TierOverrides) -> bool {
    ov.max_hosts.is_none()
        && ov.min_poll_interval_secs.is_none()
        && ov.per_host_requests_per_minute.is_none()
        && ov.max_bundle_mb.is_none()
}

// ---------------------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------------------

pub async fn list_tenant_users(
    State(state): State<AppState>,
    PlatformAdmin(who): PlatformAdmin,
    Path(tenant_id): Path<i64>,
) -> Response {
    match UserRepo::new(&state.db).list(tenant_id).await {
        Ok(users) => Json(
            users
                .into_iter()
                .map(|u| user_view(u, who.user_id))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "platform user list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "list failed").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct UpdateUserBody {
    /// True blocks, false unblocks. Absent leaves it alone.
    #[serde(default)]
    pub blocked: Option<bool>,
    #[serde(default)]
    pub platform_admin: Option<bool>,
}

/// Block/unblock a user, and grant/revoke the platform-admin flag.
///
/// Neither may be applied to the caller's own row. That single rule is what keeps the
/// console from being locked out of itself: a platform admin cannot block themselves and
/// cannot drop their own flag, so whoever is holding the console when the request finishes
/// still holds it. Any *other* platform admin can be demoted, which is how you remove one.
pub async fn update_user(
    State(state): State<AppState>,
    PlatformAdmin(who): PlatformAdmin,
    Path(user_id): Path<i64>,
    Json(body): Json<UpdateUserBody>,
) -> Response {
    if body.blocked.is_none() && body.platform_admin.is_none() {
        return (StatusCode::BAD_REQUEST, "nothing to change").into_response();
    }
    if user_id == who.user_id {
        return (
            StatusCode::BAD_REQUEST,
            "you cannot block or demote your own account",
        )
            .into_response();
    }

    let users = UserRepo::new(&state.db);
    let target = match users.get_any(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
        }
    };

    if let Some(blocked) = body.blocked {
        if blocked != target.is_blocked() {
            if let Err(e) = users.set_blocked(user_id, blocked).await {
                tracing::error!(error = %e, "set_blocked failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response();
            }
            crate::audit::record(
                &state,
                target.tenant_id,
                Some(who.user_id),
                if blocked {
                    "user.blocked"
                } else {
                    "user.unblocked"
                },
                "user",
                &user_id.to_string(),
                Some(&serde_json::json!({
                    "email": target.email,
                    "by": "platform",
                    "actor": actor_email(&state, who.user_id).await,
                })),
            )
            .await;
        }
    }

    if let Some(is_admin) = body.platform_admin {
        if is_admin != target.is_platform_admin {
            if let Err(e) = users.set_platform_admin(user_id, is_admin).await {
                tracing::error!(error = %e, "set_platform_admin failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response();
            }
            crate::audit::record(
                &state,
                target.tenant_id,
                Some(who.user_id),
                if is_admin {
                    "user.platform_admin_granted"
                } else {
                    "user.platform_admin_revoked"
                },
                "user",
                &user_id.to_string(),
                Some(&serde_json::json!({
                    "email": target.email,
                    "by": "platform",
                    "actor": actor_email(&state, who.user_id).await,
                })),
            )
            .await;
            if !is_admin && state.config.is_bootstrap_platform_admin(&target.email) {
                tracing::warn!(
                    email = %target.email,
                    "platform-admin flag revoked for an address listed in PLATFORM_ADMIN_EMAILS \
                     — the next restart will grant it again"
                );
            }
        }
    }

    match users.get_any(user_id).await {
        Ok(Some(u)) => Json(user_view(u, who.user_id)).into_response(),
        _ => StatusCode::NO_CONTENT.into_response(),
    }
}

/// Delete a user outright, from any tenant.
///
/// Two refusals, both about leaving something reachable afterwards: not yourself, and not a
/// tenant's last owner. The second is the one rule this console adds over the tenant-scoped
/// version, which refuses to remove *any* owner — from out here, removing a redundant owner
/// is legitimate, but stranding a tenant with nobody who can manage it is not. Blocking is
/// the reversible answer for a last owner who has to be stopped.
pub async fn delete_user(
    State(state): State<AppState>,
    PlatformAdmin(who): PlatformAdmin,
    Path(user_id): Path<i64>,
) -> Response {
    if user_id == who.user_id {
        return (
            StatusCode::BAD_REQUEST,
            "you cannot delete your own account",
        )
            .into_response();
    }

    let users = UserRepo::new(&state.db);
    let target = match users.get_any(user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "user lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
        }
    };

    if target.role == Role::Owner {
        match users.count_owners(target.tenant_id).await {
            Ok(n) if n <= 1 => {
                return (
                    StatusCode::CONFLICT,
                    "this is the tenant's only owner — block the account instead, \
                     or delete it once another owner exists",
                )
                    .into_response()
            }
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "owner count failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
            }
        }
    }

    match users.delete(target.tenant_id, user_id).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "platform user delete failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response();
        }
    }

    crate::audit::record(
        &state,
        target.tenant_id,
        Some(who.user_id),
        "user.deleted",
        "user",
        &user_id.to_string(),
        Some(&serde_json::json!({
            "email": target.email,
            "role": target.role,
            "by": "platform",
            "actor": actor_email(&state, who.user_id).await,
        })),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

// ---------------------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------------------

pub async fn get_settings(State(state): State<AppState>, _: PlatformAdmin) -> Response {
    match settings::signups_enabled(&state.db).await {
        Ok(signups_enabled) => Json(SettingsView {
            signups_enabled,
            on_prem: state.config.on_prem,
        })
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "settings read failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "read failed").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct SettingsBody {
    pub signups_enabled: bool,
}

pub async fn put_settings(
    State(state): State<AppState>,
    PlatformAdmin(who): PlatformAdmin,
    Json(body): Json<SettingsBody>,
) -> Response {
    if let Err(e) =
        settings::set_signups_enabled(&state.db, body.signups_enabled, who.user_id).await
    {
        tracing::error!(error = %e, "settings write failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response();
    }

    // The switch belongs to the whole install, but `audit_log.tenant_id` is NOT NULL — so
    // this is recorded against the acting admin's own tenant, which is where they would go
    // looking for what they changed.
    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "platform.signups_changed",
        "platform",
        settings::SIGNUPS_ENABLED,
        Some(&serde_json::json!({ "signups_enabled": body.signups_enabled })),
    )
    .await;
    tracing::info!(
        signups_enabled = body.signups_enabled,
        user_id = who.user_id,
        "self-service signup switched"
    );

    Json(SettingsView {
        signups_enabled: body.signups_enabled,
        on_prem: state.config.on_prem,
    })
    .into_response()
}

/// Unauthenticated: the sign-in page needs to know whether to offer a signup link, and the
/// signup endpoint's own answer would come too late. Deliberately says nothing else.
pub async fn public_config(State(state): State<AppState>) -> Response {
    // On-prem refuses signup regardless of the switch, so report the effective answer
    // rather than the stored one.
    let enabled = !state.config.on_prem
        && settings::signups_enabled(&state.db)
            .await
            .unwrap_or_else(|e| {
                tracing::error!(error = %e, "public config settings read failed");
                false
            });
    Json(PublicConfigView {
        signups_enabled: enabled,
        on_prem: state.config.on_prem,
    })
    .into_response()
}

/// The acting admin's address, for audit metadata a tenant will read. Best-effort: the audit
/// write itself is best-effort, and a missing address is not worth failing the action over.
async fn actor_email(state: &AppState, user_id: i64) -> Option<String> {
    UserRepo::new(&state.db)
        .get_any(user_id)
        .await
        .ok()
        .flatten()
        .map(|u| u.email)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_rules() {
        assert!(valid_slug("acme"));
        assert!(valid_slug("acme-corp-2"));
        assert!(!valid_slug(""));
        assert!(!valid_slug("-acme"));
        assert!(!valid_slug("acme-"));
        assert!(!valid_slug("Acme"), "uppercase is not allowed");
        assert!(!valid_slug("acme corp"), "spaces reach a certificate DN");
        assert!(!valid_slug("acme.corp"));
        assert!(!valid_slug(&"a".repeat(64)));
    }

    #[test]
    fn all_null_overrides_are_no_overrides() {
        assert!(is_empty_overrides(&TierOverrides::default()));
        assert!(!is_empty_overrides(&TierOverrides {
            max_hosts: Some(10),
            ..Default::default()
        }));
    }
}
