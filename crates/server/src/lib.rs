pub mod agent_api;
pub mod agent_limits;
pub mod audit;
pub mod auth;
pub mod bundles;
pub mod config;
pub mod config_api;
pub mod desired_state;
pub mod hosts;
pub mod https;
pub mod mtls;
pub mod mux;
pub mod tenant_setup;
pub mod trial_expiry;

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
    if cfg.on_prem_admin_password.is_none() {
        tracing::warn!("ON_PREM=true but ON_PREM_ADMIN_PASSWORD unset — login will fail");
    }

    let tenants = TenantRepo::new(db);
    let users = UserRepo::new(db);
    let tenant = match tenants.get_by_slug("default").await? {
        Some(t) => t,
        None => tenants.create("default", "On-Prem", "onprem", None).await?,
    };
    if users.find_by_email(&email).await?.is_none() {
        users.create(tenant.id, &email, "owner").await?;
        tracing::info!(%email, tenant_id = tenant.id, "on-prem admin user created");
    }
    Ok(())
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/me", get(auth::handlers::me))
        .route("/api/auth/signup", post(auth::handlers::signup))
        .route("/api/auth/send-link", post(auth::handlers::send_link))
        .route("/api/auth/exchange", get(auth::handlers::exchange))
        .route("/api/auth/login", post(auth::handlers::on_prem_login))
        .route("/api/auth/logout", post(auth::handlers::logout))
        .route("/api/hosts", get(hosts::list).post(hosts::create))
        .route(
            "/api/hosts/:id",
            get(hosts::detail).delete(hosts::delete_host),
        )
        .route("/api/hosts/:id/desired", get(hosts::desired))
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
        .route("/api/bundles", get(bundles::list))
        .route("/api/bundles", post(bundles::upload))
        .route("/api/bundles/compose", post(bundles::compose))
        .route("/api/bundles/:id/config", get(bundles::get_config))
        .route("/api/audit", get(audit::list))
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
        .fallback(frontend)
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
    use fleet_storage::{HostCertRepo, HostRepo};

    let cert_repo = HostCertRepo::new(&state.db);
    match cert_repo.is_active(&ctx.serial_hex).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::FORBIDDEN, "cert revoked or unknown").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "is_active check failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    }
    if let Err(e) = HostRepo::new(&state.db)
        .touch_last_seen(ctx.tenant_id, &ctx.host_id)
        .await
    {
        tracing::error!(error = %e, "touch_last_seen failed");
    }
    axum::Json(serde_json::json!({})).into_response()
}
