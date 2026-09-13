pub mod admin_password;
pub mod agent_api;
pub mod agent_limits;
pub mod api_keys;
pub mod audit;
pub mod auth;
pub mod bundles;
pub mod config;
pub mod config_api;
pub mod conn;
pub mod csrf;
pub mod desired_state;
pub mod env_file;
pub mod hosts;
pub mod housekeeping;
pub mod https;
pub mod mtls;
pub mod mux;
pub mod platform;
pub mod security_headers;
pub mod shutdown;
pub mod tenant_setup;
pub mod trial_expiry;
pub mod users;

use std::sync::Arc;

use axum::{
    body::Body,
    extract::State,
    http::{header, HeaderValue, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use fleet_storage::{Db, TenantRepo, UserRepo};
use rust_embed::RustEmbed;

use crate::agent_limits::{AgentRateLimits, EnrollmentLimits};
use crate::auth::{email::EmailSender, rate_limit::AuthRateLimits, turnstile::Turnstile};
use crate::bundles::BundleStore;
use crate::config::Config;
use crate::mtls::MtlsContext;

#[derive(RustEmbed)]
#[folder = "../../web/dist/"]
struct EmbeddedFrontend;

#[derive(Clone)]
pub struct AppState {
    pub db: Db,
    pub config: Config,
    pub email: EmailSender,
    pub turnstile: Turnstile,
    pub rate_limits: AuthRateLimits,
    pub agent_limits: AgentRateLimits,
    pub enrollment_limits: EnrollmentLimits,
    pub trust_store: MtlsContext,
    pub mtls_server_cert_pem: Arc<String>,
    pub bundle_store: Arc<dyn BundleStore>,
    /// Memoized desired state, invalidated by the tenant's `config_version`. Shared across
    /// clones of `AppState` — one cache per process.
    pub desired_state_cache: Arc<crate::desired_state::DesiredStateCache>,
}

/// Narrow a directory we own to owner-only access.
///
/// Best-effort and Unix-only: a failure is logged, not fatal, because a deployment that has
/// deliberately widened a directory should not be unable to start. Windows has no mode bits
/// worth setting here — the on-prem Windows install is a single-administrator machine and
/// inherits the parent ACL.
pub fn restrict_dir(path: &std::path::Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            tracing::warn!(path = %path.display(), error = %e, "could not restrict directory permissions");
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

async fn healthz(State(state): State<AppState>) -> Response {
    match state.db.ping().await {
        Ok(_) => (StatusCode::OK, "OK").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "healthz: db check failed");
            (StatusCode::SERVICE_UNAVAILABLE, "db unavailable").into_response()
        }
    }
}

async fn frontend(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    let resolved = if path.is_empty() { "index.html" } else { path };

    if let Some(file) = EmbeddedFrontend::get(resolved) {
        let mime = mime_guess::from_path(resolved).first_or_octet_stream();
        return Response::builder()
            .header(
                header::CONTENT_TYPE,
                HeaderValue::from_str(mime.as_ref())
                    .unwrap_or(HeaderValue::from_static("application/octet-stream")),
            )
            .body(Body::from(file.data.into_owned()))
            .unwrap();
    }

    if let Some(index) = EmbeddedFrontend::get("index.html") {
        return Response::builder()
            .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(Body::from(index.data.into_owned()))
            .unwrap();
    }

    (StatusCode::NOT_FOUND, "frontend not built").into_response()
}

pub async fn ensure_on_prem_admin(db: &Db, cfg: &Config) -> anyhow::Result<()> {
    if !cfg.on_prem {
        return Ok(());
    }
    let email = match cfg.on_prem_admin_email.as_deref() {
        Some(e) => e.to_lowercase(),
        None => {
            tracing::warn!("ON_PREM=true but ON_PREM_ADMIN_EMAIL unset — no admin user created");
            return Ok(());
        }
    };
    // The hash is the preferred of the two and startup refuses both at once, so checking
    // only the plaintext meant every install that did the recommended thing was told at
    // every start that its working login would fail.
    if cfg.on_prem_admin_password.is_none() && cfg.on_prem_admin_password_hash.is_none() {
        tracing::warn!(
            "ON_PREM=true but neither ON_PREM_ADMIN_PASSWORD nor ON_PREM_ADMIN_PASSWORD_HASH              is set — login will fail. Produce a hash with `nsclient-fleet --hash-password`."
        );
    }

    let tenants = TenantRepo::new(db);
    let users = UserRepo::new(db);
    let tenant = match tenants.get_by_slug("default").await? {
        Some(t) => t,
        None => tenants.create("default", "On-Prem", "onprem", None).await?,
    };
    if users.find_by_email(&email).await?.is_none() {
        users
            .create(tenant.id, &email, fleet_core::user::Role::Owner)
            .await?;
        tracing::info!(%email, tenant_id = tenant.id, "on-prem admin user created");
    }
    Ok(())
}

/// Grant the platform-admin flag to every address in `PLATFORM_ADMIN_EMAILS` that has an
/// account, at startup.
///
/// Only ever grants. Revoking is a console action, and having the env var quietly undo it on
/// the next deploy would make the console's toggle a lie for anyone listed here — the log
/// line on revoke says as much. An address with no account yet is normal on a fresh install:
/// `platform_admin_bootstrap` picks it up the moment that account is created.
pub async fn ensure_platform_admins(db: &Db, cfg: &Config) -> anyhow::Result<()> {
    let users = UserRepo::new(db);
    for email in &cfg.platform_admin_emails {
        match users.promote_platform_admin_by_email(email).await? {
            Some(user_id) => {
                tracing::info!(%email, user_id, "platform admin granted from PLATFORM_ADMIN_EMAILS")
            }
            None => {
                tracing::debug!(%email, "platform admin already granted, or no such account yet")
            }
        }
    }
    Ok(())
}

/// Grant the flag to a user who has just *signed in*, if their address is in the bootstrap
/// list. This is what makes `PLATFORM_ADMIN_EMAILS` work on a brand-new install, where the
/// operator sets the variable and then signs up.
///
/// Called from `issue_session_cookie` — the one place a session is minted — and deliberately
/// not at row creation. A row is created by whoever asked for it; a session means the
/// address was proven, by a redeemed magic link or the on-prem password. See the call site
/// for what granting at creation allowed a tenant admin to do.
pub(crate) async fn platform_admin_bootstrap(state: &AppState, user: &fleet_core::user::User) {
    if !state.config.is_bootstrap_platform_admin(&user.email) {
        return;
    }
    if user.is_platform_admin {
        return;
    }
    match UserRepo::new(&state.db)
        .set_platform_admin(user.id, true)
        .await
    {
        Ok(_) => tracing::info!(
            email = %user.email,
            user_id = user.id,
            "platform admin granted from PLATFORM_ADMIN_EMAILS on sign-in"
        ),
        Err(e) => tracing::error!(error = %e, "platform admin bootstrap failed"),
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/me", get(auth::handlers::me))
        .route("/api/auth/signup", post(auth::handlers::signup))
        .route("/api/auth/send-link", post(auth::handlers::send_link))
        .route(
            "/api/auth/exchange",
            get(auth::handlers::exchange).post(auth::handlers::exchange_confirm),
        )
        .route("/api/auth/login", post(auth::handlers::on_prem_login))
        .route("/api/auth/logout", post(auth::handlers::logout))
        .route(
            "/api/auth/logout-all",
            post(auth::handlers::logout_everywhere),
        )
        .route("/api/hosts", get(hosts::list).post(hosts::create))
        .route("/api/hosts/bulk-delete", post(hosts::bulk_delete))
        .route("/api/hosts/bulk-tags", post(hosts::bulk_tags))
        .route(
            "/api/hosts/:id",
            get(hosts::detail).delete(hosts::delete_host),
        )
        .route("/api/hosts/:id/desired", get(hosts::desired))
        .route(
            "/api/hosts/:id/revoke-certs",
            post(hosts::revoke_host_certs),
        )
        .route(
            "/api/hosts/:id/tags/:key",
            axum::routing::put(config_api::put_tag),
        )
        .route(
            "/api/hosts/:id/tags/:key",
            axum::routing::delete(config_api::delete_tag),
        )
        .route(
            "/api/hosts/:id/override",
            axum::routing::put(config_api::put_override),
        )
        .route(
            "/api/hosts/:id/override",
            axum::routing::delete(config_api::delete_override),
        )
        .route("/api/groups", get(config_api::list_groups))
        .route("/api/groups", post(config_api::create_group))
        .route(
            "/api/groups/:id",
            axum::routing::patch(config_api::patch_group),
        )
        .route(
            "/api/groups/:id",
            axum::routing::delete(config_api::delete_group),
        )
        .route("/api/groups/preview", post(config_api::preview_selector))
        .route(
            "/api/groups/:id/bundles",
            get(bundles::list_for_group).post(bundles::assign_to_group),
        )
        .route(
            "/api/groups/:id/bundles/:bundle_id",
            axum::routing::delete(bundles::unassign_from_group),
        )
        // The body limit is scoped to this one route on purpose. axum's 2 MiB default
        // applied to the upload, so every tier limit above 2 MB was unreachable — the
        // body was refused before the handler that checks the tier ever ran. Raising it
        // globally would hand the same allowance to every JSON route instead.
        .route("/api/bundles", get(bundles::list))
        .route(
            "/api/bundles",
            post(bundles::upload).layer(axum::extract::DefaultBodyLimit::max(
                fleet_core::tier::MAX_BUNDLE_MB_ANY_TIER as usize * 1024 * 1024,
            )),
        )
        .route(
            "/api/bundle-key",
            get(bundles::get_bundle_key).put(bundles::set_bundle_key),
        )
        .route("/api/bundles/compose", post(bundles::compose))
        .route(
            "/api/bundles/:id",
            axum::routing::delete(bundles::delete_bundle),
        )
        .route("/api/bundles/:id/config", get(bundles::get_config))
        .route("/api/bundles/:id/download", get(bundles::ui_download))
        .route("/api/audit", get(audit::list))
        .route("/api/keys", get(api_keys::list).post(api_keys::create))
        .route("/api/keys/:id", axum::routing::delete(api_keys::delete_key))
        .route("/api/users", get(users::list).post(users::invite))
        .route(
            "/api/users/:id",
            axum::routing::patch(users::set_role).delete(users::delete_user),
        )
        // Anonymous: the sign-in page asks whether signup is open before it can offer it.
        .route("/api/public-config", get(platform::public_config))
        // Cross-tenant administration. Every handler below takes the `PlatformAdmin`
        // extractor — see the module docs for why the check lives in the signature.
        .route(
            "/api/platform/tenants",
            get(platform::list_tenants).post(platform::create_tenant),
        )
        .route(
            "/api/platform/tenants/:id/subscription",
            axum::routing::put(platform::put_subscription),
        )
        .route(
            "/api/platform/tenants/:id/users",
            get(platform::list_tenant_users),
        )
        .route(
            "/api/platform/users/:id",
            axum::routing::patch(platform::update_user).delete(platform::delete_user),
        )
        .route("/api/platform/tiers", get(platform::list_tiers))
        .route(
            "/api/platform/settings",
            get(platform::get_settings).put(platform::put_settings),
        )
        .route("/enroll/v1", post(hosts::enroll))
        // Layers wrap the inner service; later .layer() = outer = runs first on the request.
        // We want session_layer to run FIRST (so AuthedUser is in extensions), then trial_expiry.
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            trial_expiry::trial_expiry_layer,
        ))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            auth::middleware::session_layer,
        ))
        // Outside the session layer, so a refused cross-origin request never reaches the
        // point of resolving who it claims to be.
        .layer(axum::middleware::from_fn(csrf::layer))
        .fallback(frontend)
        // Outermost, and deliberately after `.fallback`, so the headers reach the SPA and
        // every error response as well as the API routes.
        .layer(axum::middleware::from_fn_with_state(
            security_headers::SecurityHeaders::from_config(&state.config),
            security_headers::layer,
        ))
        .with_state(state)
}

/// The mTLS-only router served on LISTEN_MTLS. Routes here trust that an upstream
/// `MtlsContext` has already verified the client cert and inserted `PeerHostContext`.
pub fn mtls_router(state: AppState) -> Router {
    Router::new()
        .route("/agent/v1/heartbeat", get(agent_heartbeat))
        .route("/agent/v1/desired-state", get(agent_api::desired_state))
        .route("/agent/v1/state-report", post(agent_api::state_report))
        .route("/agent/v1/renew", post(agent_api::renew))
        .route("/agent/v1/bundles/:id", get(bundles::download))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            agent_limits::tier_layer,
        ))
        .with_state(state)
}

async fn agent_heartbeat(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<crate::mtls::PeerHostContext>,
) -> Response {
    // Revocation is checked in `tier_layer`, which wraps every agent route including this one,
    // so a cert that reaches here is already active. Heartbeat only refreshes liveness.
    if let Err(e) = fleet_storage::HostRepo::new(&state.db)
        .touch_last_seen(ctx.tenant_id, &ctx.host_id)
        .await
    {
        tracing::error!(error = %e, "touch_last_seen failed");
    }
    axum::Json(serde_json::json!({})).into_response()
}
