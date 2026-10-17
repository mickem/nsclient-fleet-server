//! Audit log: write entries on key state-changing actions and expose `GET /api/audit` for
//! operators to read them back. Writes are best-effort — a DB failure here logs but does NOT
//! fail the calling request, since the underlying mutation has already succeeded by the
//! point we record. (For compliance regimes that require audit-or-rollback, this would need
//! to be reworked; v1 doesn't promise that.)

use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_storage::{AuditRepo, AuditRow};
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::AppState;

const QUERY_HARD_CAP: i64 = 1_000;

/// Best-effort write. Logs and continues on failure.
pub async fn record(
    state: &AppState,
    tenant_id: i64,
    user_id: Option<i64>,
    action: &str,
    target_type: &str,
    target_id: &str,
    metadata: Option<&serde_json::Value>,
) {
    if let Err(e) = AuditRepo::new(&state.db)
        .record(tenant_id, user_id, action, target_type, target_id, metadata)
        .await
    {
        tracing::error!(error = %e, action, "audit write failed");
    }
}

#[derive(Deserialize)]
pub struct AuditQuery {
    /// Action prefix filter — e.g. `bundle.` matches `bundle.uploaded` and `bundle.assigned`.
    #[serde(default)]
    pub action: Option<String>,
    /// Unix-second cutoff; only entries with `ts >= since` are returned.
    #[serde(default)]
    pub since: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
}

#[derive(Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub user_id: Option<i64>,
    pub ts: i64,
    pub metadata: Option<serde_json::Value>,
}

pub async fn list(
    State(state): State<AppState>,
    who: AuthedUser,
    Query(q): Query<AuditQuery>,
) -> Response {
    let limit = q.limit.unwrap_or(100).clamp(1, QUERY_HARD_CAP);
    match AuditRepo::new(&state.db)
        .list(who.tenant_id, q.action.as_deref(), q.since, limit)
        .await
    {
        Ok(rows) => Json(rows.into_iter().map(map_entry).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "audit list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

fn map_entry(r: AuditRow) -> AuditEntry {
    AuditEntry {
        id: r.id,
        action: r.action,
        target_type: r.target_type,
        target_id: r.target_id,
        user_id: r.user_id,
        ts: r.ts,
        metadata: r.metadata_json.and_then(|s| serde_json::from_str(&s).ok()),
    }
}
