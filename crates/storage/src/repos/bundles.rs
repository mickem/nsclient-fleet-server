use anyhow::Result;
use fleet_core::time::now_unix;
use sqlx::{AssertSqlSafe, Row};

use crate::Db;

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
    /// 'plain' or 'enc-v1' (see `fleet_core::encbundle`).
    pub format: String,
    /// Hex fingerprint of the client-held encryption key; `None` for plain bundles.
    pub key_fingerprint: Option<String>,
}

pub struct BundlesRepo<'a> {
    db: &'a Db,
}

impl<'a> BundlesRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    #[allow(clippy::too_many_arguments)]
    /// Insert a bundle under an id the caller has already chosen.
    ///
    /// The id used to be generated here, which meant the signature could not cover it — it
    /// did not exist until after the row did. A signature that says nothing about which
    /// bundle it is for is most of the reason v1 signatures were worth so little; see
    /// [`fleet_core::bundlesig`].
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        id: &str,
        tenant_id: i64,
        name: &str,
        version: &str,
        sha256: &str,
        size_bytes: i64,
        signature: &str,
        format: &str,
        key_fingerprint: Option<&str>,
    ) -> Result<BundleRow> {
        let id = id.to_string();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO bundles (id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at, format, key_fingerprint)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(name)
        .bind(version)
        .bind(sha256)
        .bind(size_bytes)
        .bind(signature)
        .bind(now)
        .bind(format)
        .bind(key_fingerprint)
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
            format: format.to_owned(),
            key_fingerprint: key_fingerprint.map(str::to_owned),
        })
    }

    pub async fn get(&self, tenant_id: i64, id: &str) -> Result<Option<BundleRow>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at, format, key_fingerprint
             FROM bundles WHERE tenant_id = ? AND id = ?",
        )
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_bundle))
    }

    pub async fn count(&self, tenant_id: i64) -> Result<i64> {
        Ok(
            sqlx::query_scalar("SELECT COUNT(*) FROM bundles WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_one(&self.db.read)
                .await?,
        )
    }

    /// Delete a bundle and every assignment referencing it, in one transaction.
    ///
    /// The assignments have to go with it or a group keeps pointing at a bundle that is not
    /// there, and the next desired-state computation for every host in that group fails.
    /// The stored bytes are the caller's to remove — this layer does not know where they
    /// live — and are deleted after this returns true.
    pub async fn delete(&self, tenant_id: i64, id: &str) -> Result<bool> {
        let mut tx = self.db.write.begin().await?;
        sqlx::query("DELETE FROM bundle_assignments WHERE tenant_id = ? AND bundle_id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        let res = sqlx::query("DELETE FROM bundles WHERE tenant_id = ? AND id = ?")
            .bind(tenant_id)
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(res.rows_affected() > 0)
    }

    /// Every bundle in the database, across tenants. For the startup re-sign only.
    pub async fn list_all(&self) -> Result<Vec<BundleRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at,
                    format, key_fingerprint
             FROM bundles",
        )
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_bundle).collect())
    }

    /// Replace a bundle's signature. Startup re-sign only — bundles are otherwise immutable.
    pub async fn replace_signature(&self, tenant_id: i64, id: &str, signature: &str) -> Result<()> {
        sqlx::query("UPDATE bundles SET signature = ? WHERE tenant_id = ? AND id = ?")
            .bind(signature)
            .bind(tenant_id)
            .bind(id)
            .execute(&self.db.write)
            .await?;
        Ok(())
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<BundleRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at, format, key_fingerprint
             FROM bundles WHERE tenant_id = ? ORDER BY uploaded_at DESC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_bundle).collect())
    }

    /// Every version of one bundle, oldest first.
    pub async fn list_by_name(&self, tenant_id: i64, name: &str) -> Result<Vec<BundleRow>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, version, sha256, size_bytes, signature, uploaded_at, format, key_fingerprint
             FROM bundles WHERE tenant_id = ? AND name = ? ORDER BY uploaded_at, id",
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_bundle).collect())
    }

    /// Rename every version of bundle `from` to `to`, in one transaction that also bumps
    /// the tenant's `config_version`.
    ///
    /// `in_place` versions keep their id and bytes; only the name and the signature over
    /// the new identity change. That is every plain version: agents take the name from the
    /// signed desired state, and the desired-state hash covers the whole descriptor, so
    /// hosts in sync are told about the new name without the bytes being touched.
    ///
    /// `moved` versions had to change bytes — encrypted ones bind the name into their AAD —
    /// so each becomes a new row under a new id whose bytes the caller has already stored,
    /// and the old row's group assignments move to it before the old row goes. Overwriting
    /// bytes in place would leave a window, or after a failed write a permanent state, where
    /// a row's signature and its bytes disagree.
    ///
    /// The version bump is in the transaction so no poll can see the new rows under the old
    /// version, and it lands before the caller deletes any replaced bytes: a cached state
    /// still naming an old id is never served after its file is gone.
    ///
    /// Changes nothing unless every version the caller read is still there under `from`,
    /// nothing else is (a version saved under the old name meanwhile would be left behind),
    /// and `to` is still free.
    pub async fn rename(
        &self,
        tenant_id: i64,
        from: &str,
        to: &str,
        in_place: &[RenamedInPlace],
        moved: &[MovedBundle],
    ) -> Result<RenameOutcome> {
        let mut tx = self.db.write.begin().await?;
        let taken: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM bundles WHERE tenant_id = ? AND name = ?")
                .bind(tenant_id)
                .bind(to)
                .fetch_one(&mut *tx)
                .await?;
        if taken > 0 {
            return Ok(RenameOutcome::NameTaken);
        }
        for r in in_place {
            let res = sqlx::query(
                "UPDATE bundles SET name = ?, signature = ?
                 WHERE tenant_id = ? AND id = ? AND name = ?",
            )
            .bind(to)
            .bind(&r.signature)
            .bind(tenant_id)
            .bind(&r.id)
            .bind(from)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                return Ok(RenameOutcome::Changed);
            }
        }
        for r in moved {
            let res = sqlx::query(
                "INSERT INTO bundles (id, tenant_id, name, version, sha256, size_bytes, signature,
                                      uploaded_at, format, key_fingerprint)
                 SELECT ?, tenant_id, ?, version, ?, ?, ?, uploaded_at, format, ?
                 FROM bundles WHERE tenant_id = ? AND id = ? AND name = ?",
            )
            .bind(&r.new_id)
            .bind(to)
            .bind(&r.sha256)
            .bind(r.size_bytes)
            .bind(&r.signature)
            .bind(&r.key_fingerprint)
            .bind(tenant_id)
            .bind(&r.old_id)
            .bind(from)
            .execute(&mut *tx)
            .await?;
            if res.rows_affected() != 1 {
                return Ok(RenameOutcome::Changed);
            }
            sqlx::query(
                "UPDATE bundle_assignments SET bundle_id = ? WHERE tenant_id = ? AND bundle_id = ?",
            )
            .bind(&r.new_id)
            .bind(tenant_id)
            .bind(&r.old_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM bundles WHERE tenant_id = ? AND id = ?")
                .bind(tenant_id)
                .bind(&r.old_id)
                .execute(&mut *tx)
                .await?;
        }
        let left: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM bundles WHERE tenant_id = ? AND name = ?")
                .bind(tenant_id)
                .bind(from)
                .fetch_one(&mut *tx)
                .await?;
        if left > 0 {
            return Ok(RenameOutcome::Changed);
        }
        sqlx::query("UPDATE tenants SET config_version = config_version + 1 WHERE id = ?")
            .bind(tenant_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(RenameOutcome::Renamed)
    }
}

/// A bundle version renamed in place: same id and bytes, a signature over the new name.
#[derive(Debug, Clone)]
pub struct RenamedInPlace {
    pub id: String,
    pub signature: String,
}

/// A bundle version whose bytes changed with its name, stored under a new id.
#[derive(Debug, Clone)]
pub struct MovedBundle {
    pub old_id: String,
    pub new_id: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub signature: String,
    pub key_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenameOutcome {
    Renamed,
    /// `to` was taken by the time the transaction ran.
    NameTaken,
    /// A version was deleted, renamed or added under `from` since the caller read them.
    Changed,
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
        format: r.get("format"),
        key_fingerprint: r.get("key_fingerprint"),
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
            "SELECT b.id, b.tenant_id, b.name, b.version, b.sha256, b.size_bytes, b.signature, b.uploaded_at, b.format, b.key_fingerprint, ba.priority
             FROM bundle_assignments ba
             INNER JOIN bundles b ON b.id = ba.bundle_id
             WHERE ba.tenant_id = ? AND ba.group_id IN ({placeholders})"
        );
        let mut q = sqlx::query(AssertSqlSafe(sql)).bind(tenant_id);
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
        format: r.get("format"),
        key_fingerprint: r.get("key_fingerprint"),
    }
}
