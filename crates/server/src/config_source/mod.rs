//! Groups and bundles from a directory of files instead of the UI (`CONFIG_SOURCE_DIR`).
//!
//! For an install that wants its configuration in git: the directory is the source of
//! truth, and the server reads it at startup and on `POST /api/config-source/reload`. While
//! it is set, every API route that changes groups, bundles or assignments refuses — two
//! places to edit the same thing is two versions of it.
//!
//! Single-tenant only: the directory belongs to the on-prem `default` tenant. The database
//! still holds the rows and everything downstream reads them from there; see [`reconcile`].
//! [`export`] goes the other way, and with `--import-config` is how an install moves between
//! the two.
//!
//! - [`layout`] is the directory format and its reader.
//! - [`reconcile`] makes the database match a directory.
//! - [`export`] writes the database out as one.

pub mod export;
mod layout;
pub mod reconcile;

use std::path::PathBuf;
use std::sync::Mutex;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_storage::{Db, TenantRepo};
use serde::{Deserialize, Serialize};

pub use export::{export, ExportReport};
pub use reconcile::{reconcile, ReconcileError, ReloadReport};

use crate::auth::AuthedUser;
use crate::AppState;

/// The slug of the one tenant a configuration directory can belong to: the tenant the
/// on-prem bootstrap creates.
pub const TENANT_SLUG: &str = "default";

/// The tenant a configuration directory applies to, for the server and for the export and
/// import commands alike.
pub async fn resolve_tenant(db: &Db) -> anyhow::Result<i64> {
    match TenantRepo::new(db).get_by_slug(TENANT_SLUG).await? {
        Some(t) => Ok(t.id),
        None => anyhow::bail!(
            "configuration files are for single-tenant (ON_PREM=true) installs, and there is \
             no '{TENANT_SLUG}' tenant — set ON_PREM=true and ON_PREM_ADMIN_EMAIL and start \
             the server once"
        ),
    }
}

/// The configuration directory a server is running from, and how the last reload went.
pub struct ConfigSource {
    pub dir: PathBuf,
    pub tenant_id: i64,
    /// One reload at a time: two would each plan against the rows the other is replacing.
    reload_lock: tokio::sync::Mutex<()>,
    last: Mutex<Option<ReloadStatus>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReloadStatus {
    /// Unix seconds.
    pub at: i64,
    pub ok: bool,
    /// Why it failed, one entry per problem. Empty when `ok`.
    pub errors: Vec<String>,
    pub report: Option<ReloadReport>,
}

impl ConfigSource {
    pub fn new(dir: PathBuf, tenant_id: i64) -> Self {
        Self {
            dir,
            tenant_id,
            reload_lock: tokio::sync::Mutex::new(()),
            last: Mutex::new(None),
        }
    }

    pub fn last_status(&self) -> Option<ReloadStatus> {
        self.last.lock().expect("poisoned").clone()
    }

    /// Apply the directory, or with `dry_run` say what applying it would change. A dry run
    /// is not recorded as the last reload — it did not change what is being served.
    pub async fn reload(
        &self,
        state: &AppState,
        dry_run: bool,
    ) -> Result<ReloadReport, ReconcileError> {
        let _guard = self.reload_lock.lock().await;
        let result = reconcile(
            &state.db,
            state.bundle_store.as_ref(),
            &state.config.master_key,
            self.tenant_id,
            &self.dir,
            dry_run,
        )
        .await;
        if !dry_run {
            let status = match &result {
                Ok(report) => ReloadStatus {
                    at: fleet_core::time::now_unix(),
                    ok: true,
                    errors: Vec::new(),
                    report: Some(report.clone()),
                },
                Err(ReconcileError::Invalid(errors)) => ReloadStatus {
                    at: fleet_core::time::now_unix(),
                    ok: false,
                    errors: errors.clone(),
                    report: None,
                },
                Err(e) => ReloadStatus {
                    at: fleet_core::time::now_unix(),
                    ok: false,
                    errors: vec![e.to_string()],
                    report: None,
                },
            };
            *self.last.lock().expect("poisoned") = Some(status);
        }
        result
    }
}

/// The startup load. A directory that does not load is logged and the server carries on
/// with what the database already has — the last configuration that did — rather than
/// refusing to start over a bad commit.
pub async fn load_at_startup(state: &AppState) {
    let Some(source) = state.config_source.as_ref() else {
        return;
    };
    match source.reload(state, false).await {
        Ok(report) => tracing::info!(
            dir = %source.dir.display(),
            changed = report.changed,
            bundles_added = report.bundles_added.len(),
            bundles_replaced = report.bundles_replaced.len(),
            bundles_removed = report.bundles_removed.len(),
            groups_added = report.groups_added.len(),
            groups_updated = report.groups_updated.len(),
            groups_removed = report.groups_removed.len(),
            "configuration loaded from CONFIG_SOURCE_DIR"
        ),
        Err(e) => tracing::error!(
            dir = %source.dir.display(),
            "CONFIG_SOURCE_DIR did not load; serving the configuration from the last load \
             that did. {e}"
        ),
    }
}

/// The refusal every group, bundle and assignment write returns while a directory is in
/// charge of `tenant_id`. `None` when it is not.
pub fn refuse_if_managed(state: &AppState, tenant_id: i64) -> Option<Response> {
    let source = state.config_source.as_ref()?;
    (source.tenant_id == tenant_id).then(|| {
        (
            StatusCode::CONFLICT,
            "groups and bundles are managed in files (CONFIG_SOURCE_DIR) — change them there \
             and reload",
        )
            .into_response()
    })
}

/// Whether `tenant_id`'s groups and bundles come from a directory. For `/api/me`.
pub fn is_managed(state: &AppState, tenant_id: i64) -> bool {
    state
        .config_source
        .as_ref()
        .is_some_and(|s| s.tenant_id == tenant_id)
}

#[derive(Serialize)]
pub struct ConfigSourceView {
    pub managed: bool,
    pub dir: Option<String>,
    pub last: Option<ReloadStatus>,
}

/// `GET /api/config-source` — whether this tenant's configuration comes from files, and how
/// the last reload went.
pub async fn status(State(state): State<AppState>, who: AuthedUser) -> Response {
    let view = match state.config_source.as_ref() {
        Some(s) if s.tenant_id == who.tenant_id => ConfigSourceView {
            managed: true,
            dir: Some(s.dir.display().to_string()),
            last: s.last_status(),
        },
        _ => ConfigSourceView {
            managed: false,
            dir: None,
            last: None,
        },
    };
    Json(view).into_response()
}

#[derive(Deserialize)]
pub struct ReloadBody {
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Serialize)]
struct ReloadErrors {
    errors: Vec<String>,
}

/// `POST /api/config-source/reload` — re-read the directory and apply it. What a deploy
/// hook calls after `git pull`, with an API key.
pub async fn reload(
    State(state): State<AppState>,
    who: AuthedUser,
    body: axum::body::Bytes,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let Some(source) = state
        .config_source
        .as_ref()
        .filter(|s| s.tenant_id == who.tenant_id)
    else {
        return (
            StatusCode::CONFLICT,
            "configuration is not managed in files (CONFIG_SOURCE_DIR is not set)",
        )
            .into_response();
    };
    // The body is optional — a hook posting nothing reloads for real.
    let dry_run = if body.is_empty() {
        false
    } else {
        match serde_json::from_slice::<ReloadBody>(&body) {
            Ok(b) => b.dry_run,
            Err(e) => return (StatusCode::BAD_REQUEST, format!("bad body: {e}")).into_response(),
        }
    };
    match source.reload(&state, dry_run).await {
        Ok(report) => {
            if report.changed && !dry_run {
                crate::admin::audit::record(
                    &state,
                    who.tenant_id,
                    Some(who.user_id),
                    "config.reloaded",
                    "config_source",
                    &source.dir.display().to_string(),
                    serde_json::to_value(&report).ok().as_ref(),
                )
                .await;
            }
            Json(report).into_response()
        }
        Err(ReconcileError::Invalid(errors)) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(ReloadErrors { errors }),
        )
            .into_response(),
        Err(ReconcileError::Changed) => (
            StatusCode::CONFLICT,
            "groups or bundles changed during the reload — try again",
        )
            .into_response(),
        Err(ReconcileError::Internal(e)) => {
            tracing::error!(error = %e, "configuration reload failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}
