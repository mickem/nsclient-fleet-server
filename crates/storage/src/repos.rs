use anyhow::Result;
use fleet_core::api_key::ApiKey;
use fleet_core::host::{new_host_id, Host};
use fleet_core::session::Session;
use fleet_core::tenant::Tenant;
use fleet_core::time::now_unix;
use fleet_core::user::{Role, User};
use sqlx::Row;

use crate::Db;

pub struct TenantRepo<'a> {
    db: &'a Db,
}

impl<'a> TenantRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        slug: &str,
        name: &str,
        tier: &str,
        trial_expires_at: Option<i64>,
    ) -> Result<Tenant> {
        let now = now_unix();
        let row = sqlx::query(
            "INSERT INTO tenants (slug, name, tier, trial_expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)
             RETURNING id, config_version",
        )
        .bind(slug)
        .bind(name)
        .bind(tier)
        .bind(trial_expires_at)
        .bind(now)
        .fetch_one(&self.db.write)
        .await?;

        Ok(Tenant {
            id: row.get::<i64, _>("id"),
            slug: slug.to_owned(),
            name: name.to_owned(),
            tier: tier.to_owned(),
            tier_overrides_json: None,
            trial_expires_at,
            config_version: row.get::<i64, _>("config_version"),
            created_at: now,
        })
    }

    pub async fn get(&self, tenant_id: i64) -> Result<Option<Tenant>> {
        let row = sqlx::query(
            "SELECT id, slug, name, tier, tier_overrides_json, trial_expires_at,
                    config_version, created_at
             FROM tenants WHERE id = ?",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db.read)
        .await?;

        Ok(row.map(map_tenant))
    }

    pub async fn get_by_slug(&self, slug: &str) -> Result<Option<Tenant>> {
        let row = sqlx::query(
            "SELECT id, slug, name, tier, tier_overrides_json, trial_expires_at,
                    config_version, created_at
             FROM tenants WHERE slug = ?",
        )
        .bind(slug)
        .fetch_optional(&self.db.read)
        .await?;

        Ok(row.map(map_tenant))
    }

    /// Set or clear the tier override JSON. Caller must validate against
    /// `fleet_core::tier::TierOverrides` before calling.
    pub async fn set_tier_overrides(
        &self,
        tenant_id: i64,
        overrides_json: Option<&str>,
    ) -> Result<bool> {
        let res = sqlx::query("UPDATE tenants SET tier_overrides_json = ? WHERE id = ?")
            .bind(overrides_json)
            .bind(tenant_id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Atomically increment config_version and return the new value.
    pub async fn bump_config_version(&self, tenant_id: i64) -> Result<i64> {
        let row = sqlx::query(
            "UPDATE tenants SET config_version = config_version + 1
             WHERE id = ? RETURNING config_version",
        )
        .bind(tenant_id)
        .fetch_one(&self.db.write)
        .await?;
        Ok(row.get::<i64, _>("config_version"))
    }
}

fn map_tenant(r: sqlx::sqlite::SqliteRow) -> Tenant {
    Tenant {
        id: r.get("id"),
        slug: r.get("slug"),
        name: r.get("name"),
        tier: r.get("tier"),
        tier_overrides_json: r.get("tier_overrides_json"),
        trial_expires_at: r.get("trial_expires_at"),
        config_version: r.get("config_version"),
        created_at: r.get("created_at"),
    }
}

pub struct HostRepo<'a> {
    db: &'a Db,
}

impl<'a> HostRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        tenant_id: i64,
        hostname: Option<&str>,
        os: Option<&str>,
    ) -> Result<Host> {
        let id = new_host_id();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO hosts (id, tenant_id, hostname, os, created_at) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(hostname)
        .bind(os)
        .bind(now)
        .execute(&self.db.write)
        .await?;

        Ok(Host {
            id,
            tenant_id,
            hostname: hostname.map(str::to_owned),
            os: os.map(str::to_owned),
            enrolled_at: None,
            last_seen_at: None,
            current_state_hash: None,
            bootstrap_expires_at: None,
            created_at: now,
        })
    }

    pub async fn get(&self, tenant_id: i64, host_id: &str) -> Result<Option<Host>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, hostname, os, enrolled_at, last_seen_at, current_state_hash,
                    bootstrap_expires_at, created_at
             FROM hosts WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_optional(&self.db.read)
        .await?;

        Ok(row.map(map_host))
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<Host>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, hostname, os, enrolled_at, last_seen_at, current_state_hash,
                    bootstrap_expires_at, created_at
             FROM hosts WHERE tenant_id = ? ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;

        Ok(rows.into_iter().map(map_host).collect())
    }

    /// Active hosts = enrolled, plus pending hosts created in the last 24h (so abandoned
    /// bootstrap rows don't pin tier capacity forever). Used by the tier `max_hosts` check.
    pub async fn count_active(&self, tenant_id: i64) -> Result<i64> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM hosts
             WHERE tenant_id = ?
               AND (enrolled_at IS NOT NULL
                    OR (enrolled_at IS NULL AND created_at > ?))",
        )
        .bind(tenant_id)
        .bind(now_unix() - 86_400)
        .fetch_one(&self.db.read)
        .await?;
        Ok(n)
    }

    pub async fn create_pending(
        &self,
        tenant_id: i64,
        nonce_hash: &str,
        bootstrap_expires_at: i64,
    ) -> Result<Host> {
        let id = new_host_id();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO hosts (id, tenant_id, bootstrap_nonce_hash, bootstrap_expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(nonce_hash)
        .bind(bootstrap_expires_at)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(Host {
            id,
            tenant_id,
            hostname: None,
            os: None,
            enrolled_at: None,
            last_seen_at: None,
            current_state_hash: None,
            bootstrap_expires_at: Some(bootstrap_expires_at),
            created_at: now,
        })
    }

    /// Atomic state transition: pending → enrolled. Returns true iff a matching pending
    /// host was found and updated. Burns the nonce in the same statement.
    pub async fn mark_enrolled_if_pending(
        &self,
        tenant_id: i64,
        host_id: &str,
        nonce_hash: &str,
        hostname: Option<&str>,
        os: Option<&str>,
    ) -> Result<bool> {
        let now = now_unix();
        let res = sqlx::query(
            "UPDATE hosts
             SET enrolled_at = ?,
                 hostname = COALESCE(?, hostname),
                 os = COALESCE(?, os),
                 bootstrap_nonce_hash = NULL,
                 bootstrap_expires_at = NULL
             WHERE tenant_id = ?
               AND id = ?
               AND bootstrap_nonce_hash = ?
               AND enrolled_at IS NULL
               AND bootstrap_expires_at > ?",
        )
        .bind(now)
        .bind(hostname)
        .bind(os)
        .bind(tenant_id)
        .bind(host_id)
        .bind(nonce_hash)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Delete a host and everything hanging off it (tags, overrides, certs, metrics) in
    /// one transaction. Removing the cert rows is what cuts the agent off: the mTLS
    /// heartbeat's `is_active(serial)` lookup no longer matches, so a live agent gets 403
    /// on its next call. Returns true iff the host row existed.
    pub async fn delete(&self, tenant_id: i64, host_id: &str) -> Result<bool> {
        let mut tx = self.db.write.begin().await?;
        for table in ["host_tags", "host_overrides", "host_certs"] {
            sqlx::query(&format!(
                "DELETE FROM {table} WHERE tenant_id = ? AND host_id = ?"
            ))
            .bind(tenant_id)
            .bind(host_id)
            .execute(&mut *tx)
            .await?;
        }
        let res = sqlx::query("DELETE FROM hosts WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(host_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn touch_last_seen(&self, tenant_id: i64, host_id: &str) -> Result<()> {
        sqlx::query("UPDATE hosts SET last_seen_at = ? WHERE tenant_id = ? AND id = ?")
            .bind(now_unix())
            .bind(tenant_id)
            .bind(host_id)
            .execute(&self.db.write)
            .await?;
        Ok(())
    }

    pub async fn update_current_state_hash(
        &self,
        tenant_id: i64,
        host_id: &str,
        state_hash: &str,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE hosts SET current_state_hash = ?, last_seen_at = ?
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(state_hash)
        .bind(now_unix())
        .bind(tenant_id)
        .bind(host_id)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }
}

pub struct HostTagsRepo<'a> {
    db: &'a Db,
}

impl<'a> HostTagsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Upsert agent-reported tags. Returns true iff at least one tag's value changed
    /// (so callers know whether to bump config_version).
    pub async fn upsert_agent_tags(
        &self,
        tenant_id: i64,
        host_id: &str,
        tags: &std::collections::BTreeMap<String, String>,
    ) -> Result<bool> {
        let now = now_unix();
        let mut changed = false;
        let mut tx = self.db.write.begin().await?;
        for (key, value) in tags {
            let existing: Option<String> = sqlx::query_scalar(
                "SELECT value FROM host_tags
                 WHERE host_id = ? AND key = ? AND source = 'agent'",
            )
            .bind(host_id)
            .bind(key)
            .fetch_optional(&mut *tx)
            .await?;
            if existing.as_deref() != Some(value.as_str()) {
                changed = true;
            }
            sqlx::query(
                "INSERT INTO host_tags (tenant_id, host_id, key, value, source, updated_at)
                 VALUES (?, ?, ?, ?, 'agent', ?)
                 ON CONFLICT(host_id, key, source) DO UPDATE SET
                   value = excluded.value,
                   updated_at = excluded.updated_at,
                   tenant_id = excluded.tenant_id",
            )
            .bind(tenant_id)
            .bind(host_id)
            .bind(key)
            .bind(value)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(changed)
    }

    pub async fn list_for_host(
        &self,
        tenant_id: i64,
        host_id: &str,
    ) -> Result<Vec<(String, String, String)>> {
        let rows = sqlx::query(
            "SELECT key, value, source FROM host_tags
             WHERE tenant_id = ? AND host_id = ? ORDER BY key",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("key"),
                    r.get::<String, _>("value"),
                    r.get::<String, _>("source"),
                )
            })
            .collect())
    }

    pub async fn upsert_manual_tag(
        &self,
        tenant_id: i64,
        host_id: &str,
        key: &str,
        value: &str,
    ) -> Result<bool> {
        let now = now_unix();
        let existing: Option<String> = sqlx::query_scalar(
            "SELECT value FROM host_tags WHERE host_id = ? AND key = ? AND source = 'manual'",
        )
        .bind(host_id)
        .bind(key)
        .fetch_optional(&self.db.read)
        .await?;
        let changed = existing.as_deref() != Some(value);
        sqlx::query(
            "INSERT INTO host_tags (tenant_id, host_id, key, value, source, updated_at)
             VALUES (?, ?, ?, ?, 'manual', ?)
             ON CONFLICT(host_id, key, source) DO UPDATE SET
               value = excluded.value, updated_at = excluded.updated_at,
               tenant_id = excluded.tenant_id",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(key)
        .bind(value)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(changed)
    }

    pub async fn delete_manual_tag(
        &self,
        tenant_id: i64,
        host_id: &str,
        key: &str,
    ) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM host_tags WHERE tenant_id = ? AND host_id = ? AND key = ? AND source = 'manual'",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(key)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Returns tags as map<key, list<value>> (multi-source: a key can have manual + agent values).
    pub async fn map_for_host(
        &self,
        tenant_id: i64,
        host_id: &str,
    ) -> Result<std::collections::HashMap<String, Vec<String>>> {
        let rows =
            sqlx::query("SELECT key, value FROM host_tags WHERE tenant_id = ? AND host_id = ?")
                .bind(tenant_id)
                .bind(host_id)
                .fetch_all(&self.db.read)
                .await?;
        let mut out: std::collections::HashMap<String, Vec<String>> =
            std::collections::HashMap::new();
        for r in rows {
            let k: String = r.get("key");
            let v: String = r.get("value");
            out.entry(k).or_default().push(v);
        }
        Ok(out)
    }
}

#[derive(Debug, Clone)]
pub struct GroupRow {
    pub id: String,
    pub tenant_id: i64,
    pub name: String,
    pub selector_json: String,
    pub created_at: i64,
}

pub struct GroupsRepo<'a> {
    db: &'a Db,
}

impl<'a> GroupsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        tenant_id: i64,
        name: &str,
        selector_json: &str,
    ) -> Result<GroupRow> {
        use ulid::Ulid;
        let id = Ulid::new().to_string();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO groups (id, tenant_id, name, selector_json, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(selector_json)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(GroupRow {
            id,
            tenant_id,
            name: name.to_owned(),
            selector_json: selector_json.to_owned(),
            created_at: now,
        })
    }

    pub async fn update(
        &self,
        tenant_id: i64,
        id: &str,
        name: Option<&str>,
        selector_json: Option<&str>,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE groups SET
               name = COALESCE(?, name),
               selector_json = COALESCE(?, selector_json)
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(name)
        .bind(selector_json)
        .bind(tenant_id)
        .bind(id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn delete(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM groups WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get(&self, tenant_id: i64, id: &str) -> Result<Option<GroupRow>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, selector_json, created_at
             FROM groups WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_group))
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<GroupRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, selector_json, created_at
             FROM groups WHERE tenant_id = ? ORDER BY name",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_group).collect())
    }
}

fn map_group(r: sqlx::sqlite::SqliteRow) -> GroupRow {
    GroupRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        selector_json: r.get("selector_json"),
        created_at: r.get("created_at"),
    }
}

#[derive(Debug, Clone)]
pub struct BundleRow {
    pub id: String,
    pub tenant_id: i64,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub signature: String,
    pub uploaded_at: i64,
}

pub struct BundlesRepo<'a> {
    db: &'a Db,
}

impl<'a> BundlesRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: i64,
        name: &str,
        version: &str,
        sha256: &str,
        size_bytes: i64,
        signature: &str,
    ) -> Result<BundleRow> {
        use ulid::Ulid;
        let id = Ulid::new().to_string();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO bundles (id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(version)
        .bind(sha256)
        .bind(size_bytes)
        .bind(signature)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(BundleRow {
            id,
            tenant_id,
            name: name.to_owned(),
            version: version.to_owned(),
            sha256: sha256.to_owned(),
            size_bytes,
            signature: signature.to_owned(),
            uploaded_at: now,
        })
    }

    pub async fn get(&self, tenant_id: i64, id: &str) -> Result<Option<BundleRow>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at
             FROM bundles WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_bundle))
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<BundleRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at
             FROM bundles WHERE tenant_id = ? ORDER BY uploaded_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_bundle).collect())
    }
}

fn map_bundle(r: sqlx::sqlite::SqliteRow) -> BundleRow {
    BundleRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        version: r.get("version"),
        sha256: r.get("sha256"),
        size_bytes: r.get("size_bytes"),
        signature: r.get("signature"),
        uploaded_at: r.get("uploaded_at"),
    }
}

pub struct BundleAssignmentsRepo<'a> {
    db: &'a Db,
}

impl<'a> BundleAssignmentsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn assign(
        &self,
        tenant_id: i64,
        group_id: &str,
        bundle_id: &str,
        priority: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO bundle_assignments (tenant_id, group_id, bundle_id, priority, assigned_at)
             VALUES (?, ?, ?, ?, ?)
             ON CONFLICT(group_id, bundle_id) DO UPDATE SET priority = excluded.priority",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(bundle_id)
        .bind(priority)
        .bind(now_unix())
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    pub async fn unassign(&self, tenant_id: i64, group_id: &str, bundle_id: &str) -> Result<bool> {
        let res = sqlx::query(
            "DELETE FROM bundle_assignments
             WHERE tenant_id = ? AND group_id = ? AND bundle_id = ?",
        )
        .bind(tenant_id)
        .bind(group_id)
        .bind(bundle_id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// All (bundle_id, priority) pairs assigned to any of the given group ids, with bundle metadata.
    pub async fn list_for_groups(
        &self,
        tenant_id: i64,
        group_ids: &[String],
    ) -> Result<Vec<(BundleRow, i64)>> {
        if group_ids.is_empty() {
            return Ok(vec![]);
        }
        let placeholders = group_ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT b.id, b.tenant_id, b.name, b.version, b.sha256, b.size_bytes, b.signature, b.uploaded_at, ba.priority
             FROM bundle_assignments ba
             INNER JOIN bundles b ON b.id = ba.bundle_id
             WHERE ba.tenant_id = ? AND ba.group_id IN ({placeholders})"
        );
        let mut q = sqlx::query(&sql).bind(tenant_id);
        for gid in group_ids {
            q = q.bind(gid);
        }
        let rows = q.fetch_all(&self.db.read).await?;
        Ok(rows
            .into_iter()
            .map(|r| (map_bundle_partial(&r), r.get::<i64, _>("priority")))
            .collect())
    }
}

fn map_bundle_partial(r: &sqlx::sqlite::SqliteRow) -> BundleRow {
    BundleRow {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        name: r.get("name"),
        version: r.get("version"),
        sha256: r.get("sha256"),
        size_bytes: r.get("size_bytes"),
        signature: r.get("signature"),
        uploaded_at: r.get("uploaded_at"),
    }
}

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

pub struct StoredHostOverride {
    pub host_id: String,
    pub patch_encrypted: Vec<u8>,
    pub priority: i64,
}

pub struct HostOverridesRepo<'a> {
    db: &'a Db,
}

impl<'a> HostOverridesRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn upsert(
        &self,
        tenant_id: i64,
        host_id: &str,
        patch_encrypted: &[u8],
        priority: i64,
        updated_by_user: Option<i64>,
    ) -> Result<()> {
        let now = now_unix();
        sqlx::query(
            "INSERT INTO host_overrides
             (tenant_id, host_id, patch_encrypted, priority, updated_at, updated_by_user)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(host_id) DO UPDATE SET
               patch_encrypted = excluded.patch_encrypted,
               priority = excluded.priority,
               updated_at = excluded.updated_at,
               updated_by_user = excluded.updated_by_user,
               tenant_id = excluded.tenant_id",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(patch_encrypted)
        .bind(priority)
        .bind(now)
        .bind(updated_by_user)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    pub async fn delete(&self, tenant_id: i64, host_id: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM host_overrides WHERE tenant_id = ? AND host_id = ?")
            .bind(tenant_id)
            .bind(host_id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn get(&self, tenant_id: i64, host_id: &str) -> Result<Option<StoredHostOverride>> {
        let row = sqlx::query(
            "SELECT host_id, patch_encrypted, priority FROM host_overrides
             WHERE tenant_id = ? AND host_id = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| StoredHostOverride {
            host_id: r.get("host_id"),
            patch_encrypted: r.get("patch_encrypted"),
            priority: r.get("priority"),
        }))
    }
}

fn map_host(r: sqlx::sqlite::SqliteRow) -> Host {
    Host {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        hostname: r.get("hostname"),
        os: r.get("os"),
        enrolled_at: r.get("enrolled_at"),
        last_seen_at: r.get("last_seen_at"),
        current_state_hash: r.get("current_state_hash"),
        bootstrap_expires_at: r.get("bootstrap_expires_at"),
        created_at: r.get("created_at"),
    }
}

pub struct StoredTenantSecrets {
    pub tenant_id: i64,
    pub ca_cert_pem: String,
    pub ca_key_encrypted: Vec<u8>,
    pub ca_subject_dn: String,
    pub bundle_signing_pub_pem: String,
    pub bundle_signing_key_encrypted: Vec<u8>,
}

pub struct CaSummary {
    pub tenant_id: i64,
    pub tenant_slug: String,
    pub ca_cert_pem: String,
    pub ca_subject_dn: String,
}

pub struct TenantSecretsRepo<'a> {
    db: &'a Db,
}

impl<'a> TenantSecretsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: i64,
        ca_cert_pem: &str,
        ca_key_encrypted: &[u8],
        ca_subject_dn: &str,
        bundle_signing_pub_pem: &str,
        bundle_signing_key_encrypted: &[u8],
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_secrets
             (tenant_id, ca_cert_pem, ca_key_encrypted, ca_subject_dn,
              bundle_signing_pub_pem, bundle_signing_key_encrypted, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(tenant_id)
        .bind(ca_cert_pem)
        .bind(ca_key_encrypted)
        .bind(ca_subject_dn)
        .bind(bundle_signing_pub_pem)
        .bind(bundle_signing_key_encrypted)
        .bind(now_unix())
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    pub async fn get_by_tenant(&self, tenant_id: i64) -> Result<Option<StoredTenantSecrets>> {
        let row = sqlx::query(
            "SELECT tenant_id, ca_cert_pem, ca_key_encrypted, ca_subject_dn,
                    bundle_signing_pub_pem, bundle_signing_key_encrypted
             FROM tenant_secrets WHERE tenant_id = ?",
        )
        .bind(tenant_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| StoredTenantSecrets {
            tenant_id: r.get("tenant_id"),
            ca_cert_pem: r.get("ca_cert_pem"),
            ca_key_encrypted: r.get("ca_key_encrypted"),
            ca_subject_dn: r.get("ca_subject_dn"),
            bundle_signing_pub_pem: r.get("bundle_signing_pub_pem"),
            bundle_signing_key_encrypted: r.get("bundle_signing_key_encrypted"),
        }))
    }

    pub async fn list_all_cas(&self) -> Result<Vec<CaSummary>> {
        let rows = sqlx::query(
            "SELECT s.tenant_id, t.slug AS tenant_slug, s.ca_cert_pem, s.ca_subject_dn
             FROM tenant_secrets s INNER JOIN tenants t ON t.id = s.tenant_id",
        )
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| CaSummary {
                tenant_id: r.get("tenant_id"),
                tenant_slug: r.get("tenant_slug"),
                ca_cert_pem: r.get("ca_cert_pem"),
                ca_subject_dn: r.get("ca_subject_dn"),
            })
            .collect())
    }

    pub async fn lookup_by_ca_subject_dn(&self, subject_dn: &str) -> Result<Option<(i64, String)>> {
        let row = sqlx::query(
            "SELECT s.tenant_id, t.slug AS tenant_slug
             FROM tenant_secrets s INNER JOIN tenants t ON t.id = s.tenant_id
             WHERE s.ca_subject_dn = ?",
        )
        .bind(subject_dn)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(|r| {
            (
                r.get::<i64, _>("tenant_id"),
                r.get::<String, _>("tenant_slug"),
            )
        }))
    }
}

pub struct HostCertRepo<'a> {
    db: &'a Db,
}

impl<'a> HostCertRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn record(
        &self,
        tenant_id: i64,
        host_id: &str,
        serial: &str,
        fingerprint_sha256: &str,
        issued_at: i64,
        expires_at: i64,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO host_certs
             (tenant_id, host_id, serial, fingerprint_sha256, issued_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(serial)
        .bind(fingerprint_sha256)
        .bind(issued_at)
        .bind(expires_at)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    pub async fn is_active(&self, serial: &str) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 AS x FROM host_certs WHERE serial = ? AND revoked_at IS NULL LIMIT 1",
        )
        .bind(serial)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.is_some())
    }
}

pub struct UserRepo<'a> {
    db: &'a Db,
}

impl<'a> UserRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(&self, tenant_id: i64, email: &str, role: Role) -> Result<User> {
        let now = now_unix();
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO users (tenant_id, email, role, created_at) VALUES (?, ?, ?, ?) RETURNING id",
        )
        .bind(tenant_id)
        .bind(email)
        .bind(role.as_db())
        .bind(now)
        .fetch_one(&self.db.write)
        .await?;

        Ok(User {
            id,
            tenant_id,
            email: email.to_owned(),
            role,
            created_at: now,
        })
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, email, role, created_at
             FROM users WHERE tenant_id = ? ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_user).collect())
    }

    pub async fn set_role(&self, tenant_id: i64, user_id: i64, role: Role) -> Result<bool> {
        let res = sqlx::query("UPDATE users SET role = ? WHERE tenant_id = ? AND id = ?")
            .bind(role.as_db())
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Remove a user and everything that would dangle behind them.
    ///
    /// Sessions and outstanding magic links are deleted, which signs the user out
    /// immediately. Audit entries and host overrides they authored are kept but lose their
    /// attribution (`user_id`/`updated_by_user` set to NULL) — the record of *what* happened
    /// outlives the account, and both columns are nullable for exactly this reason.
    pub async fn delete(&self, tenant_id: i64, user_id: i64) -> Result<bool> {
        let mut tx = self.db.write.begin().await?;

        sqlx::query("DELETE FROM sessions WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM magic_links WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        // NOT NULL reference: these must go, and revoking a departing user's automation is
        // the point of deleting them in the first place.
        sqlx::query("DELETE FROM api_keys WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("UPDATE audit_log SET user_id = NULL WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "UPDATE host_overrides SET updated_by_user = NULL
             WHERE tenant_id = ? AND updated_by_user = ?",
        )
        .bind(tenant_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        let res = sqlx::query("DELETE FROM users WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(res.rows_affected() == 1)
    }

    pub async fn get(&self, tenant_id: i64, user_id: i64) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, email, role, created_at
             FROM users WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_user))
    }

    pub async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, email, role, created_at FROM users WHERE email = ? LIMIT 1",
        )
        .bind(email)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_user))
    }
}

fn map_user(r: sqlx::sqlite::SqliteRow) -> User {
    User {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        email: r.get("email"),
        role: Role::from_db(&r.get::<String, _>("role")),
        created_at: r.get("created_at"),
    }
}

pub struct MagicLinkRepo<'a> {
    db: &'a Db,
}

impl<'a> MagicLinkRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        token_hash: &str,
        tenant_id: i64,
        user_id: i64,
        expires_at: i64,
    ) -> Result<()> {
        let now = now_unix();
        sqlx::query(
            "INSERT INTO magic_links (token_hash, tenant_id, user_id, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(token_hash)
        .bind(tenant_id)
        .bind(user_id)
        .bind(expires_at)
        .bind(now)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Burn a magic link atomically — only succeeds if it exists, hasn't been used, and isn't expired.
    pub async fn redeem(&self, token_hash: &str) -> Result<Option<(i64, i64)>> {
        let now = now_unix();
        let row = sqlx::query(
            "UPDATE magic_links
             SET used_at = ?
             WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?
             RETURNING tenant_id, user_id",
        )
        .bind(now)
        .bind(token_hash)
        .bind(now)
        .fetch_optional(&self.db.write)
        .await?;
        Ok(row.map(|r| (r.get::<i64, _>("tenant_id"), r.get::<i64, _>("user_id"))))
    }

    pub async fn delete_expired(&self) -> Result<u64> {
        let now = now_unix();
        let res = sqlx::query("DELETE FROM magic_links WHERE expires_at < ?")
            .bind(now)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }
}

pub struct ApiKeyRepo<'a> {
    db: &'a Db,
}

impl<'a> ApiKeyRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    /// Store a key. `token_hash` must already be hashed by the caller — the plaintext never
    /// reaches this layer.
    pub async fn create(
        &self,
        tenant_id: i64,
        user_id: i64,
        name: &str,
        token_hash: &str,
        token_prefix: &str,
    ) -> Result<ApiKey> {
        let id = ulid::Ulid::new().to_string();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO api_keys (id, tenant_id, user_id, name, token_hash, token_prefix, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(token_prefix)
        .bind(now)
        .execute(&self.db.write)
        .await?;

        Ok(ApiKey {
            id,
            tenant_id,
            user_id,
            name: name.to_owned(),
            token_prefix: token_prefix.to_owned(),
            created_at: now,
            last_used_at: None,
        })
    }

    pub async fn list_for_user(&self, tenant_id: i64, user_id: i64) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, user_id, name, token_prefix, created_at, last_used_at
             FROM api_keys WHERE tenant_id = ? AND user_id = ? ORDER BY created_at DESC",
        )
        .bind(tenant_id)
        .bind(user_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_api_key).collect())
    }

    /// Resolve a presented token to its owner. Returns the key id alongside, so the caller
    /// can record use without a second lookup.
    ///
    /// Looked up by hash — a leaked database yields no usable tokens.
    pub async fn find_by_hash(&self, token_hash: &str) -> Result<Option<ApiKey>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, user_id, name, token_prefix, created_at, last_used_at
             FROM api_keys WHERE token_hash = ?",
        )
        .bind(token_hash)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_api_key))
    }

    pub async fn touch_last_used(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE api_keys SET last_used_at = ? WHERE id = ?")
            .bind(now_unix())
            .bind(id)
            .execute(&self.db.write)
            .await?;
        Ok(())
    }

    /// Scoped to the owner: a key can only be revoked by the user it belongs to.
    pub async fn delete(&self, tenant_id: i64, user_id: i64, id: &str) -> Result<bool> {
        let res =
            sqlx::query("DELETE FROM api_keys WHERE tenant_id = ? AND user_id = ? AND id = ?")
                .bind(tenant_id)
                .bind(user_id)
                .bind(id)
                .execute(&self.db.write)
                .await?;
        Ok(res.rows_affected() == 1)
    }
}

fn map_api_key(r: sqlx::sqlite::SqliteRow) -> ApiKey {
    ApiKey {
        id: r.get("id"),
        tenant_id: r.get("tenant_id"),
        user_id: r.get("user_id"),
        name: r.get("name"),
        token_prefix: r.get("token_prefix"),
        created_at: r.get("created_at"),
        last_used_at: r.get("last_used_at"),
    }
}

pub struct SessionRepo<'a> {
    db: &'a Db,
}

impl<'a> SessionRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn create(
        &self,
        id_hash: &str,
        tenant_id: i64,
        user_id: i64,
        ttl_seconds: i64,
    ) -> Result<Session> {
        let now = now_unix();
        let expires_at = now + ttl_seconds;
        sqlx::query(
            "INSERT INTO sessions (id, tenant_id, user_id, expires_at, last_used_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id_hash)
        .bind(tenant_id)
        .bind(user_id)
        .bind(expires_at)
        .bind(now)
        .bind(now)
        .execute(&self.db.write)
        .await?;

        Ok(Session {
            id_hash: id_hash.to_owned(),
            tenant_id,
            user_id,
            expires_at,
            last_used_at: now,
            created_at: now,
        })
    }

    /// Fetch a session by token hash, refreshing `last_used_at`. Returns None if missing or expired.
    pub async fn touch(&self, id_hash: &str) -> Result<Option<Session>> {
        let now = now_unix();
        let row = sqlx::query(
            "UPDATE sessions
             SET last_used_at = ?
             WHERE id = ? AND expires_at > ?
             RETURNING id, tenant_id, user_id, expires_at, last_used_at, created_at",
        )
        .bind(now)
        .bind(id_hash)
        .bind(now)
        .fetch_optional(&self.db.write)
        .await?;
        Ok(row.map(|r| Session {
            id_hash: r.get::<String, _>("id"),
            tenant_id: r.get("tenant_id"),
            user_id: r.get("user_id"),
            expires_at: r.get("expires_at"),
            last_used_at: r.get("last_used_at"),
            created_at: r.get("created_at"),
        }))
    }

    pub async fn delete(&self, id_hash: &str) -> Result<()> {
        sqlx::query("DELETE FROM sessions WHERE id = ?")
            .bind(id_hash)
            .execute(&self.db.write)
            .await?;
        Ok(())
    }

    pub async fn delete_expired(&self) -> Result<u64> {
        let now = now_unix();
        let res = sqlx::query("DELETE FROM sessions WHERE expires_at < ?")
            .bind(now)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{open, run_migrations};
    use tempfile::TempDir;

    async fn test_db() -> (TempDir, Db) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.db");
        let db = open(&path).await.unwrap();
        run_migrations(&db.write).await.unwrap();
        (dir, db)
    }

    #[tokio::test]
    async fn wal_mode_is_enabled() {
        let (_dir, db) = test_db().await;
        let mode: String = sqlx::query_scalar("PRAGMA journal_mode")
            .fetch_one(&db.read)
            .await
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[tokio::test]
    async fn create_tenant_and_host_roundtrip() {
        let (_dir, db) = test_db().await;
        let tenants = TenantRepo::new(&db);
        let hosts = HostRepo::new(&db);

        let tenant = tenants
            .create("acme", "Acme Corp", "free", None)
            .await
            .unwrap();
        assert!(tenant.id > 0);
        assert_eq!(tenant.config_version, 0);
        assert_eq!(tenant.tier, "free");

        let by_slug = tenants.get_by_slug("acme").await.unwrap().unwrap();
        assert_eq!(by_slug, tenant);

        let host = hosts
            .create(tenant.id, Some("db-01"), Some("windows"))
            .await
            .unwrap();
        assert_eq!(host.tenant_id, tenant.id);

        let fetched = hosts.get(tenant.id, &host.id).await.unwrap().unwrap();
        assert_eq!(fetched, host);

        let cross_tenant = hosts.get(tenant.id + 999, &host.id).await.unwrap();
        assert!(cross_tenant.is_none());
    }

    #[tokio::test]
    async fn foreign_keys_are_enforced() {
        let (_dir, db) = test_db().await;
        let result = sqlx::query("INSERT INTO hosts (id, tenant_id, created_at) VALUES (?, ?, ?)")
            .bind("01HXXXXXXXXXXXXXXXXXXXXXXX")
            .bind(99999_i64)
            .bind(0_i64)
            .execute(&db.write)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn magic_link_redeem_is_single_use() {
        let (_dir, db) = test_db().await;
        let tenants = TenantRepo::new(&db);
        let users = UserRepo::new(&db);
        let links = MagicLinkRepo::new(&db);

        let t = tenants.create("acme", "Acme", "free", None).await.unwrap();
        let u = users
            .create(t.id, "a@b", fleet_core::user::Role::Owner)
            .await
            .unwrap();

        let now = now_unix();
        links.create("hash1", t.id, u.id, now + 900).await.unwrap();

        let first = links.redeem("hash1").await.unwrap();
        assert_eq!(first, Some((t.id, u.id)));

        let second = links.redeem("hash1").await.unwrap();
        assert!(second.is_none(), "second redeem must fail");
    }

    #[tokio::test]
    async fn magic_link_expired_rejected() {
        let (_dir, db) = test_db().await;
        let tenants = TenantRepo::new(&db);
        let users = UserRepo::new(&db);
        let links = MagicLinkRepo::new(&db);

        let t = tenants.create("acme", "Acme", "free", None).await.unwrap();
        let u = users
            .create(t.id, "a@b", fleet_core::user::Role::Owner)
            .await
            .unwrap();

        links
            .create("hash_expired", t.id, u.id, now_unix() - 1)
            .await
            .unwrap();
        assert!(links.redeem("hash_expired").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn session_lifecycle() {
        let (_dir, db) = test_db().await;
        let tenants = TenantRepo::new(&db);
        let users = UserRepo::new(&db);
        let sessions = SessionRepo::new(&db);

        let t = tenants.create("acme", "Acme", "free", None).await.unwrap();
        let u = users
            .create(t.id, "a@b", fleet_core::user::Role::Owner)
            .await
            .unwrap();

        let s = sessions
            .create("session_hash", t.id, u.id, 3600)
            .await
            .unwrap();
        assert!(s.expires_at > now_unix());

        let touched = sessions.touch("session_hash").await.unwrap().unwrap();
        assert_eq!(touched.user_id, u.id);

        sessions.delete("session_hash").await.unwrap();
        assert!(sessions.touch("session_hash").await.unwrap().is_none());
    }
}
