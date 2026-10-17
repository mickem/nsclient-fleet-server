use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_storage::{BundleAssignmentsRepo, BundlesRepo, GroupsRepo, TenantRepo};
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::AppState;

#[derive(Deserialize)]
pub struct AssignBody {
    pub bundle_id: String,
    #[serde(default = "default_priority")]
    pub priority: i64,
}

fn default_priority() -> i64 {
    100
}

pub async fn assign_to_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(group_id): Path<String>,
    Json(body): Json<AssignBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if GroupsRepo::new(&state.db)
        .get(who.tenant_id, &group_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    }
    if BundlesRepo::new(&state.db)
        .get(who.tenant_id, &body.bundle_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "bundle not found").into_response();
    }

    if let Err(e) = BundleAssignmentsRepo::new(&state.db)
        .assign(who.tenant_id, &group_id, &body.bundle_id, body.priority)
        .await
    {
        tracing::error!(error = %e, "assign failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    }
    if let Err(e) = TenantRepo::new(&state.db)
        .bump_config_version(who.tenant_id)
        .await
    {
        tracing::error!(error = %e, "config_version bump failed");
    }
    crate::admin::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "bundle.assigned",
        "group",
        &group_id,
        Some(&serde_json::json!({
            "bundle_id": body.bundle_id,
            "priority": body.priority,
        })),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
pub struct AssignmentView {
    pub bundle_id: String,
    pub name: String,
    pub version: String,
    pub priority: i64,
}

/// `GET /api/groups/:id/bundles` — the bundles assigned to one group, with priorities.
pub async fn list_for_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(group_id): Path<String>,
) -> Response {
    if GroupsRepo::new(&state.db)
        .get(who.tenant_id, &group_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    }
    match BundleAssignmentsRepo::new(&state.db)
        .list_for_groups(who.tenant_id, &[group_id])
        .await
    {
        Ok(rows) => {
            let mut views: Vec<AssignmentView> = rows
                .into_iter()
                .map(|(b, priority)| AssignmentView {
                    bundle_id: b.id,
                    name: b.name,
                    version: b.version,
                    priority,
                })
                .collect();
            views.sort_by_key(|v| v.priority);
            Json(views).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "assignment list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `DELETE /api/groups/:id/bundles/:bundle_id` — remove an assignment.
pub async fn unassign_from_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path((group_id, bundle_id)): Path<(String, String)>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    match BundleAssignmentsRepo::new(&state.db)
        .unassign(who.tenant_id, &group_id, &bundle_id)
        .await
    {
        Ok(true) => {
            if let Err(e) = TenantRepo::new(&state.db)
                .bump_config_version(who.tenant_id)
                .await
            {
                tracing::error!(error = %e, "config_version bump failed");
            }
            crate::admin::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "bundle.unassigned",
                "group",
                &group_id,
                Some(&serde_json::json!({ "bundle_id": bundle_id })),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "assignment not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "unassign failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}
