//! HTTP CRUD for tags, groups, and host overrides (Phase 5b).

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::selector::Selector;
use fleet_storage::{GroupsRepo, HostOverridesRepo, HostRepo, HostTagsRepo, TenantRepo};
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::AppState;

// ---- Tags (manual source) -----------------------------------------------------------------

#[derive(Deserialize)]
pub struct PutTagBody {
    pub value: String,
}

pub async fn put_tag(
    State(state): State<AppState>,
    who: AuthedUser,
    Path((host_id, key)): Path<(String, String)>,
    Json(body): Json<PutTagBody>,
) -> Response {
    if !host_belongs_to(&state, who.tenant_id, &host_id).await {
        return (StatusCode::NOT_FOUND, "host not found").into_response();
    }
    if key.trim().is_empty() || key.len() > 128 {
        return (StatusCode::BAD_REQUEST, "invalid key").into_response();
    }
    let tags = HostTagsRepo::new(&state.db);
    let changed = match tags
        .upsert_manual_tag(who.tenant_id, &host_id, &key, &body.value)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "tag upsert failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if changed {
        bump_config_version(&state, who.tenant_id).await;
    }
    StatusCode::NO_CONTENT.into_response()
}

pub async fn delete_tag(
    State(state): State<AppState>,
    who: AuthedUser,
    Path((host_id, key)): Path<(String, String)>,
) -> Response {
    if !host_belongs_to(&state, who.tenant_id, &host_id).await {
        return (StatusCode::NOT_FOUND, "host not found").into_response();
    }
    let tags = HostTagsRepo::new(&state.db);
    match tags.delete_manual_tag(who.tenant_id, &host_id, &key).await {
        Ok(true) => {
            bump_config_version(&state, who.tenant_id).await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tag delete failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

// ---- Groups -------------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateGroupBody {
    pub name: String,
    pub selector: serde_json::Value,
}

#[derive(Deserialize)]
pub struct PatchGroupBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub selector: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct GroupView {
    pub id: String,
    pub name: String,
    pub selector: serde_json::Value,
    pub created_at: i64,
}

pub async fn create_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<CreateGroupBody>,
) -> Response {
    if body.name.trim().is_empty() || body.name.len() > 128 {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }
    let selector = match Selector::from_json(&body.selector) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad selector: {e}")).into_response(),
    };
    let selector_json = serde_json::to_string(&selector).unwrap_or_else(|_| "{}".to_string());
    let groups = GroupsRepo::new(&state.db);
    match groups
        .create(who.tenant_id, &body.name, &selector_json)
        .await
    {
        Ok(g) => {
            bump_config_version(&state, who.tenant_id).await;
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "group.created",
                "group",
                &g.id,
                Some(&serde_json::json!({ "name": g.name })),
            )
            .await;
            (
                StatusCode::CREATED,
                Json(GroupView {
                    id: g.id,
                    name: g.name,
                    selector: serde_json::from_str(&g.selector_json)
                        .unwrap_or(serde_json::json!({})),
                    created_at: g.created_at,
                }),
            )
                .into_response()
        }
        Err(e) => {
            // Likely UNIQUE(tenant_id, name) violation
            tracing::info!(error = %e, "group create failed");
            (StatusCode::CONFLICT, "name already exists").into_response()
        }
    }
}

pub async fn patch_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(group_id): Path<String>,
    Json(body): Json<PatchGroupBody>,
) -> Response {
    let selector_json = match &body.selector {
        Some(v) => match Selector::from_json(v) {
            Ok(s) => Some(serde_json::to_string(&s).unwrap_or_else(|_| "{}".to_string())),
            Err(e) => {
                return (StatusCode::BAD_REQUEST, format!("bad selector: {e}")).into_response()
            }
        },
        None => None,
    };
    let groups = GroupsRepo::new(&state.db);
    match groups
        .update(
            who.tenant_id,
            &group_id,
            body.name.as_deref(),
            selector_json.as_deref(),
        )
        .await
    {
        Ok(true) => {
            bump_config_version(&state, who.tenant_id).await;
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "group.updated",
                "group",
                &group_id,
                Some(&serde_json::json!({ "name": body.name })),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "group update failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

pub async fn delete_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(group_id): Path<String>,
) -> Response {
    let groups = GroupsRepo::new(&state.db);
    match groups.delete(who.tenant_id, &group_id).await {
        Ok(true) => {
            bump_config_version(&state, who.tenant_id).await;
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "group.deleted",
                "group",
                &group_id,
                None,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            // FK violation: still has assignments
            tracing::info!(error = %e, "group delete refused");
            (
                StatusCode::CONFLICT,
                "group has bundle assignments — remove them first",
            )
                .into_response()
        }
    }
}

pub async fn list_groups(State(state): State<AppState>, who: AuthedUser) -> Response {
    let groups = GroupsRepo::new(&state.db);
    match groups.list(who.tenant_id).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|g| GroupView {
                    id: g.id,
                    name: g.name,
                    selector: serde_json::from_str(&g.selector_json)
                        .unwrap_or(serde_json::json!({})),
                    created_at: g.created_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "group list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct PreviewBody {
    pub selector: serde_json::Value,
}

#[derive(Serialize)]
pub struct PreviewMatch {
    pub id: String,
    pub hostname: Option<String>,
}

/// `POST /api/groups/preview` — evaluate a selector against every host's tags and return the
/// matching hosts, without saving anything. Backs the "membership preview" in the group editor.
pub async fn preview_selector(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<PreviewBody>,
) -> Response {
    let selector = match Selector::from_json(&body.selector) {
        Ok(s) => s,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("bad selector: {e}")).into_response(),
    };
    let hosts = match HostRepo::new(&state.db).list(who.tenant_id).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "host list failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let tags_repo = HostTagsRepo::new(&state.db);
    let mut matches = Vec::new();
    for h in hosts {
        let tags = match tags_repo.map_for_host(who.tenant_id, &h.id).await {
            Ok(t) => t,
            Err(e) => {
                tracing::error!(error = %e, "tags map failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        };
        if selector.matches(&tags) {
            matches.push(PreviewMatch {
                id: h.id,
                hostname: h.hostname,
            });
        }
    }
    Json(matches).into_response()
}

// ---- Host overrides (encrypted at rest) ---------------------------------------------------

#[derive(Deserialize)]
pub struct PutOverrideBody {
    pub patch: serde_json::Value,
    #[serde(default)]
    pub priority: Option<i64>,
}

pub async fn put_override(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
    Json(body): Json<PutOverrideBody>,
) -> Response {
    if !host_belongs_to(&state, who.tenant_id, &host_id).await {
        return (StatusCode::NOT_FOUND, "host not found").into_response();
    }
    let patch_str = match serde_json::to_string(&body.patch) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "invalid patch").into_response(),
    };
    let encrypted = state.config.master_key.encrypt(patch_str.as_bytes());
    let priority = body.priority.unwrap_or(1000);

    let repo = HostOverridesRepo::new(&state.db);
    if let Err(e) = repo
        .upsert(
            who.tenant_id,
            &host_id,
            &encrypted,
            priority,
            Some(who.user_id),
        )
        .await
    {
        tracing::error!(error = %e, "override upsert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    }
    bump_config_version(&state, who.tenant_id).await;
    // Audit entry — payload is intentionally NOT included so secrets never land in audit_log.
    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "host.override.updated",
        "host",
        &host_id,
        Some(&serde_json::json!({ "priority": priority })),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

pub async fn delete_override(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
) -> Response {
    if !host_belongs_to(&state, who.tenant_id, &host_id).await {
        return (StatusCode::NOT_FOUND, "host not found").into_response();
    }
    let repo = HostOverridesRepo::new(&state.db);
    match repo.delete(who.tenant_id, &host_id).await {
        Ok(true) => {
            bump_config_version(&state, who.tenant_id).await;
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "host.override.deleted",
                "host",
                &host_id,
                None,
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "override delete failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

// ---- helpers ------------------------------------------------------------------------------

async fn host_belongs_to(state: &AppState, tenant_id: i64, host_id: &str) -> bool {
    HostRepo::new(&state.db)
        .get(tenant_id, host_id)
        .await
        .map(|h| h.is_some())
        .unwrap_or(false)
}

async fn bump_config_version(state: &AppState, tenant_id: i64) {
    if let Err(e) = TenantRepo::new(&state.db)
        .bump_config_version(tenant_id)
        .await
    {
        tracing::error!(error = %e, "config_version bump failed");
    }
}
