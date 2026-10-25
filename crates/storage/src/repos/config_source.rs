use std::collections::BTreeSet;

use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::Row;

use crate::Db;

/// A tenant's groups, bundles and assignments replaced wholesale from a configuration
/// directory — the write side of `--import-config`.
///
/// The caller works the plan out (which rows to keep, which to replace); this applies it in
/// one transaction, so a poll never sees a group pointing at a bundle that is half gone, and
/// bumps `config_version` in the same transaction for the reason [`super::BundlesRepo::rename`]
/// does.
pub struct ConfigSourceRepo<'a> {
    db: &'a Db,
}

/// One group as the directory has it. `id` is the existing row's when a group of that name
/// is already there, so its id — which appears in the audit log and the UI's URLs — survives
/// an import.
#[derive(Debug, Clone)]
pub struct PlannedGroup {
    pub id: String,
    pub name: String,
    pub selector_json: String,
    /// True when `id` is new and the row has to be inserted.
    pub create: bool,
}

/// A bundle row to insert; its bytes are already in the store under `id`.
#[derive(Debug, Clone)]
pub struct PlannedBundle {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub signature: String,
    pub format: String,
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ConfigPlan {
    /// The bundle and group ids the plan was worked out against. If either set has moved by
    /// the time the transaction runs, nothing is applied — see [`ApplyOutcome::Changed`].
    pub expected_bundle_ids: BTreeSet<String>,
    pub expected_group_ids: BTreeSet<String>,
    pub delete_bundle_ids: Vec<String>,
    pub insert_bundles: Vec<PlannedBundle>,
    pub delete_group_ids: Vec<String>,
    pub groups: Vec<PlannedGroup>,
    /// The tenant's complete assignment set afterwards: (group id, bundle id, priority).
    pub assignments: Vec<(String, String, i64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    Applied,
    /// A bundle or group was added or removed since the plan was made.
    Changed,
}

impl<'a> ConfigSourceRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Every assignment the tenant has: (group id, bundle id, priority).
    pub async fn list_assignments(&self, tenant_id: i64) -> Result<Vec<(String, String, i64)>> {
        let rows = sqlx::query(
            "SELECT group_id, bundle_id, priority FROM bundle_assignments WHERE tenant_id = ?",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("group_id"), r.get("bundle_id"), r.get("priority")))
            .collect())
    }

    pub async fn apply(&self, tenant_id: i64, plan: &ConfigPlan) -> Result<ApplyOutcome> {
        let mut tx = self.db.write.begin().await?;

        let bundle_ids: BTreeSet<String> =
            sqlx::query_scalar("SELECT id FROM bundles WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_all(&mut *tx)
                .await?
                .into_iter()
                .collect();
        let group_ids: BTreeSet<String> =
            sqlx::query_scalar("SELECT id FROM groups WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_all(&mut *tx)
                .await?
                .into_iter()
                .collect();
        if bundle_ids != plan.expected_bundle_ids || group_ids != plan.expected_group_ids {
            return Ok(ApplyOutcome::Changed);
        }

        // Assignments first: they reference both of the tables changed below.
        sqlx::query("DELETE FROM bundle_assignments WHERE tenant_id = ?")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;

        // Deletes before inserts: a bundle whose contents changed keeps its (name, version),
        // which is unique, so the old row has to be gone before the new one goes in.
        for id in &plan.delete_bundle_ids {
            sqlx::query("DELETE FROM bundles WHERE tenant_id = ? AND id = ?")
                .bind(tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        let now = now_unix();
        for b in &plan.insert_bundles {
            sqlx::query(
                "INSERT INTO bundles (id, tenant_id, name, version, sha256, size_bytes, signature,
                                      uploaded_at, format, key_fingerprint)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&b.id)
            .bind(tenant_id)
            .bind(&b.name)
            .bind(&b.version)
            .bind(&b.sha256)
            .bind(b.size_bytes)
            .bind(&b.signature)
            .bind(now)
            .bind(&b.format)
            .bind(&b.key_fingerprint)
            .execute(&mut *tx)
            .await?;
        }

        for id in &plan.delete_group_ids {
            sqlx::query("DELETE FROM groups WHERE tenant_id = ? AND id = ?")
                .bind(tenant_id)
                .bind(id)
                .execute(&mut *tx)
                .await?;
        }
        for g in &plan.groups {
            if g.create {
                sqlx::query(
                    "INSERT INTO groups (id, tenant_id, name, selector_json, created_at)
                     VALUES (?, ?, ?, ?, ?)",
                )
                .bind(&g.id)
                .bind(tenant_id)
                .bind(&g.name)
                .bind(&g.selector_json)
                .bind(now)
                .execute(&mut *tx)
                .await?;
            } else {
                sqlx::query(
                    "UPDATE groups SET name = ?, selector_json = ? WHERE tenant_id = ? AND id = ?",
                )
                .bind(&g.name)
                .bind(&g.selector_json)
                .bind(tenant_id)
                .bind(&g.id)
                .execute(&mut *tx)
                .await?;
            }
        }

        for (group_id, bundle_id, priority) in &plan.assignments {
            sqlx::query(
                "INSERT INTO bundle_assignments (tenant_id, group_id, bundle_id, priority, assigned_at)
                 VALUES (?, ?, ?, ?, ?)",
            )
            .bind(tenant_id)
            .bind(group_id)
            .bind(bundle_id)
            .bind(priority)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query("UPDATE tenants SET config_version = config_version + 1 WHERE id = ?")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(ApplyOutcome::Applied)
    }
}
