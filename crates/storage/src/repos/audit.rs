use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::Row;

use crate::Db;

#[derive(Debug, Clone)]
pub struct AuditRow {
    pub id: i64,
    pub tenant_id: i64,
    pub user_id: Option<i64>,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub metadata_json: Option<String>,
    pub ts: i64,
}

pub struct AuditRepo<'a> {
    db: &'a Db,
}

impl<'a> AuditRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn record(
        &self,
        tenant_id: i64,
        user_id: Option<i64>,
        action: &str,
        target_type: &str,
        target_id: &str,
        metadata: Option<&serde_json::Value>,
    ) -> Result<()> {
        let metadata_json = metadata.and_then(|v| serde_json::to_string(v).ok());
        sqlx::query(
            "INSERT INTO audit_log
             (tenant_id, user_id, action, target_type, target_id, metadata_json, ts)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(tenant_id)
        .bind(user_id)
        .bind(action)
        .bind(target_type)
        .bind(target_id)
        .bind(metadata_json)
        .bind(now_unix())
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    pub async fn list(
        &self,
        tenant_id: i64,
        action_prefix: Option<&str>,
        since: Option<i64>,
        limit: i64,
    ) -> Result<Vec<AuditRow>> {
        // Most-recent-first. Two filters compose with cheap branching.
        let rows = match (action_prefix, since) {
            (Some(prefix), Some(since)) => sqlx::query(
                "SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json, ts
                 FROM audit_log
                 WHERE tenant_id = ? AND action LIKE ? AND ts >= ?
                 ORDER BY ts DESC LIMIT ?",
            )
            .bind(tenant_id)
            .bind(format!("{prefix}%"))
            .bind(since)
            .bind(limit)
            .fetch_all(&self.db.read)
            .await?,
            (Some(prefix), None) => sqlx::query(
                "SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json, ts
                 FROM audit_log
                 WHERE tenant_id = ? AND action LIKE ?
                 ORDER BY ts DESC LIMIT ?",
            )
            .bind(tenant_id)
            .bind(format!("{prefix}%"))
            .bind(limit)
            .fetch_all(&self.db.read)
            .await?,
            (None, Some(since)) => sqlx::query(
                "SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json, ts
                 FROM audit_log
                 WHERE tenant_id = ? AND ts >= ?
                 ORDER BY ts DESC LIMIT ?",
            )
            .bind(tenant_id)
            .bind(since)
            .bind(limit)
            .fetch_all(&self.db.read)
            .await?,
            (None, None) => sqlx::query(
                "SELECT id, tenant_id, user_id, action, target_type, target_id, metadata_json, ts
                 FROM audit_log
                 WHERE tenant_id = ?
                 ORDER BY ts DESC LIMIT ?",
            )
            .bind(tenant_id)
            .bind(limit)
            .fetch_all(&self.db.read)
            .await?,
        };
        Ok(rows
            .into_iter()
            .map(|r| AuditRow {
                id: r.get("id"),
                tenant_id: r.get("tenant_id"),
                user_id: r.get("user_id"),
                action: r.get("action"),
                target_type: r.get("target_type"),
                target_id: r.get("target_id"),
                metadata_json: r.get("metadata_json"),
                ts: r.get("ts"),
            })
            .collect())
    }
}
