use anyhow::Result;
use fleet_core::host::{new_host_id, Host};
use fleet_core::selector::{HostTags, TagSource, TagValue};
use fleet_core::time::now_unix;
use sqlx::{AssertSqlSafe, Row};

use crate::Db;

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
            local_config_present: None,
            host_override_last: None,
            created_at: now,
        })
    }

    pub async fn get(&self, tenant_id: i64, host_id: &str) -> Result<Option<Host>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, hostname, os, enrolled_at, last_seen_at, current_state_hash,
                    bootstrap_expires_at, local_config_present, host_override_last, created_at
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
                    bootstrap_expires_at, local_config_present, host_override_last, created_at
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
            local_config_present: None,
            host_override_last: None,
            created_at: now,
        })
    }

    /// Atomic state transition: pending → enrolled. Returns true iff a matching pending
    /// host was found and updated. Burns the nonce in the same statement.
    /// Is this host still waiting for exactly this bootstrap nonce?
    ///
    /// A read, so it can run *before* the CA-key decrypt and the ECDSA signature that
    /// enrollment otherwise pays for unconditionally. It is not the authority — the atomic
    /// burn in [`Self::enroll`] is, and it re-checks every one of these conditions in the
    /// same statement that clears them. This only stops a replayed-but-unexpired token
    /// costing a signature before being refused.
    pub async fn bootstrap_pending(
        &self,
        tenant_id: i64,
        host_id: &str,
        nonce_hash: &str,
    ) -> Result<bool> {
        let row = sqlx::query(
            "SELECT 1 AS x FROM hosts
             WHERE tenant_id = ? AND id = ? AND bootstrap_nonce_hash = ?
               AND enrolled_at IS NULL AND bootstrap_expires_at > ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(nonce_hash)
        .bind(now_unix())
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.is_some())
    }

    /// Burn the one-time bootstrap nonce and record the issued certificate together.
    ///
    /// One transaction because the two used to be separate statements: if recording the
    /// certificate failed after the burn, the host was marked enrolled with no certificate
    /// and could never enrol again — the token was spent — so the only way back was to
    /// delete and recreate it. Either both land or neither does.
    ///
    /// Returns false when the burn matched nothing: an already-used nonce, an expired one,
    /// a host that is already enrolled, or a wrong nonce. The condition lives in the UPDATE
    /// so two simultaneous enrollments cannot both succeed.
    #[allow(clippy::too_many_arguments)]
    pub async fn enroll(
        &self,
        tenant_id: i64,
        host_id: &str,
        nonce_hash: &str,
        hostname: Option<&str>,
        os: Option<&str>,
        cert: EnrolledCert<'_>,
    ) -> Result<bool> {
        let now = now_unix();
        let mut tx = self.db.write.begin().await?;

        let burned = sqlx::query(
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
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if burned != 1 {
            tx.rollback().await?;
            return Ok(false);
        }

        sqlx::query(
            "INSERT INTO host_certs
             (tenant_id, host_id, serial, fingerprint_sha256, issued_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(cert.serial)
        .bind(cert.fingerprint_sha256)
        .bind(cert.issued_at)
        .bind(cert.expires_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(true)
    }

    /// Delete a host and everything hanging off it (tags, overrides, facts, certs) in
    /// one transaction. Removing the cert rows is what cuts the agent off: the mTLS
    /// heartbeat's `standing(serial)` lookup no longer matches, so a live agent gets 403
    /// on its next call. Returns true iff the host row existed.
    pub async fn delete(&self, tenant_id: i64, host_id: &str) -> Result<bool> {
        let mut tx = self.db.write.begin().await?;
        for table in [
            "host_tags",
            "host_overrides",
            "host_facts",
            "host_fact_changes",
            "host_certs",
        ] {
            sqlx::query(AssertSqlSafe(format!(
                "DELETE FROM {table} WHERE tenant_id = ? AND host_id = ?"
            )))
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

    /// Cut a host off and hand it a way back, in one transaction.
    ///
    /// Revoking alone would strand the host: its certificates stop working and enrollment
    /// refuses a host that is already enrolled, so the only remaining move would be to
    /// delete it and lose its tags, groups and overrides. Resetting it to pending in the
    /// same transaction keeps the host's identity and everything hanging off it, and
    /// makes this the operation an operator actually wants when a key is believed stolen.
    ///
    /// Returns the number of certificates revoked, or `None` if no such host.
    pub async fn revoke_certs_and_reset_to_pending(
        &self,
        tenant_id: i64,
        host_id: &str,
        nonce_hash: &str,
        bootstrap_expires_at: i64,
    ) -> Result<Option<u64>> {
        let now = now_unix();
        let mut tx = self.db.write.begin().await?;

        let revoked = sqlx::query(
            "UPDATE host_certs SET revoked_at = ?
             WHERE tenant_id = ? AND host_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(host_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        let reset = sqlx::query(
            "UPDATE hosts
             SET enrolled_at = NULL,
                 bootstrap_nonce_hash = ?,
                 bootstrap_expires_at = ?
             WHERE tenant_id = ? AND id = ?",
        )
        .bind(nonce_hash)
        .bind(bootstrap_expires_at)
        .bind(tenant_id)
        .bind(host_id)
        .execute(&mut *tx)
        .await?
        .rows_affected();

        if reset == 0 {
            tx.rollback().await?;
            return Ok(None);
        }
        tx.commit().await?;
        Ok(Some(revoked))
    }

    /// Refresh `last_seen_at`, but only once it is older than `stale_after_secs`.
    ///
    /// For the paths that run on *every* request from every host, where an unconditional
    /// write would put a row update per host per poll on the write connection. The row is
    /// left alone while the stored value is still fresh — the condition lives in the
    /// statement so this stays one round trip that dirties no page when it matches nothing.
    pub async fn touch_last_seen_if_stale(
        &self,
        tenant_id: i64,
        host_id: &str,
        stale_after_secs: i64,
    ) -> Result<()> {
        let now = now_unix();
        sqlx::query(
            "UPDATE hosts SET last_seen_at = ?
             WHERE tenant_id = ? AND id = ? AND (last_seen_at IS NULL OR last_seen_at <= ?)",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(host_id)
        .bind(now - stale_after_secs)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    /// Record the agent's answer to "do you carry local configuration that outranks ours?".
    ///
    /// Returns true iff this *changed* the stored answer — including the first report on a
    /// host that had none, since "unknown → no" is a real transition. The WHERE clause does
    /// that comparison in the same statement rather than reading first: an agent sends this
    /// on every state report, and the overwhelmingly common case is an unchanged value that
    /// should not become a write on the single writer connection.
    pub async fn set_local_config_present(
        &self,
        tenant_id: i64,
        host_id: &str,
        present: bool,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE hosts SET local_config_present = ?
              WHERE tenant_id = ? AND id = ?
                AND (local_config_present IS NULL OR local_config_present != ?)",
        )
        .bind(i64::from(present))
        .bind(tenant_id)
        .bind(host_id)
        .bind(i64::from(present))
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    /// Record whether the host's agent applies the host override last. Same shape as
    /// [`Self::set_local_config_present`]: true iff the stored answer changed, and an
    /// unchanged answer is not a write.
    pub async fn set_host_override_last(
        &self,
        tenant_id: i64,
        host_id: &str,
        last: bool,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE hosts SET host_override_last = ?
              WHERE tenant_id = ? AND id = ?
                AND (host_override_last IS NULL OR host_override_last != ?)",
        )
        .bind(i64::from(last))
        .bind(tenant_id)
        .bind(host_id)
        .bind(i64::from(last))
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
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

    /// Replace a host's agent-reported tags with exactly `tags`.
    ///
    /// Replace, not merge: the report carries the host's full view of itself, so a key it
    /// has stopped reporting has stopped being true. Merging left those keys in place
    /// forever — an agent that reported `role=sql_server` once kept satisfying selectors
    /// over it after the role was gone, and nothing but deleting the host removed them.
    ///
    /// Manual tags are untouched. They live under the same keys with `source = 'manual'`
    /// and belong to the operator.
    ///
    /// Returns true iff the stored set actually changed, so callers know whether anything
    /// downstream needs invalidating.
    pub async fn replace_agent_tags(
        &self,
        tenant_id: i64,
        host_id: &str,
        tags: &std::collections::BTreeMap<String, String>,
    ) -> Result<bool> {
        let now = now_unix();
        let mut changed = false;
        let mut tx = self.db.write.begin().await?;

        let stale: Vec<String> = sqlx::query_scalar(
            "SELECT key FROM host_tags
             WHERE tenant_id = ? AND host_id = ? AND source = 'agent'",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_all(&mut *tx)
        .await?;
        for key in stale.iter().filter(|k| !tags.contains_key(*k)) {
            sqlx::query(
                "DELETE FROM host_tags
                 WHERE tenant_id = ? AND host_id = ? AND key = ? AND source = 'agent'",
            )
            .bind(tenant_id)
            .bind(host_id)
            .bind(key)
            .execute(&mut *tx)
            .await?;
            changed = true;
        }

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

    /// Every tag in the tenant, as `(host_id, key, value, source)`. One query for the host
    /// list, instead of one per row.
    pub async fn list_for_tenant(
        &self,
        tenant_id: i64,
    ) -> Result<Vec<(String, String, String, String)>> {
        let rows = sqlx::query(
            "SELECT host_id, key, value, source FROM host_tags
             WHERE tenant_id = ? ORDER BY host_id, key",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<String, _>("host_id"),
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

    /// Every value of tag `key` in a tenant, manual and agent alike, as `(host_id, value)`.
    pub async fn values_for_key(&self, tenant_id: i64, key: &str) -> Result<Vec<(String, String)>> {
        let rows =
            sqlx::query("SELECT host_id, value FROM host_tags WHERE tenant_id = ? AND key = ?")
                .bind(tenant_id)
                .bind(key)
                .fetch_all(&self.db.read)
                .await?;
        Ok(rows
            .into_iter()
            .map(|r| (r.get("host_id"), r.get("value")))
            .collect())
    }

    /// Every host's tags in a tenant, keyed by host id, in one query. For evaluating a
    /// selector across the fleet without a round trip per host.
    pub async fn maps_for_tenant(
        &self,
        tenant_id: i64,
    ) -> Result<std::collections::HashMap<String, HostTags>> {
        let rows =
            sqlx::query("SELECT host_id, key, value, source FROM host_tags WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_all(&self.db.read)
                .await?;
        let mut out: std::collections::HashMap<String, HostTags> = Default::default();
        for r in rows {
            out.entry(r.get("host_id"))
                .or_default()
                .entry(r.get("key"))
                .or_default()
                .push(TagValue {
                    value: r.get("value"),
                    source: TagSource::from_db(&r.get::<String, _>("source")),
                });
        }
        Ok(out)
    }

    /// Every tag on a host, keyed by tag key, with each value carrying its source.
    ///
    /// The source is part of the result and not an afterthought: selector evaluation needs
    /// it to tell an operator's assertion from a claim the host made about itself. This
    /// used to return bare strings, which is what let a host tag its way into any group.
    pub async fn map_for_host(&self, tenant_id: i64, host_id: &str) -> Result<HostTags> {
        let rows = sqlx::query(
            "SELECT key, value, source FROM host_tags WHERE tenant_id = ? AND host_id = ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .fetch_all(&self.db.read)
        .await?;
        let mut out: HostTags = std::collections::HashMap::new();
        for r in rows {
            let k: String = r.get("key");
            out.entry(k).or_default().push(TagValue {
                value: r.get("value"),
                source: TagSource::from_db(&r.get::<String, _>("source")),
            });
        }
        Ok(out)
    }
}

/// The certificate fields [`HostRepo::enroll`] records, grouped so the call reads as
/// "enrol this host with this certificate" rather than as nine positional arguments.
#[derive(Debug, Clone, Copy)]
pub struct EnrolledCert<'a> {
    pub serial: &'a str,
    pub fingerprint_sha256: &'a str,
    pub issued_at: i64,
    pub expires_at: i64,
}

pub struct StoredHostOverride {
    pub host_id: String,
    pub patch_encrypted: Vec<u8>,
    pub priority: i64,
    /// UI template the override was written with; `None` for plain INI.
    pub template: Option<String>,
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
        template: Option<&str>,
        updated_by_user: Option<i64>,
    ) -> Result<()> {
        let now = now_unix();
        sqlx::query(
            "INSERT INTO host_overrides
             (tenant_id, host_id, patch_encrypted, priority, template, updated_at, updated_by_user)
             VALUES (?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(host_id) DO UPDATE SET
               patch_encrypted = excluded.patch_encrypted,
               priority = excluded.priority,
               template = excluded.template,
               updated_at = excluded.updated_at,
               updated_by_user = excluded.updated_by_user,
               tenant_id = excluded.tenant_id",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(patch_encrypted)
        .bind(priority)
        .bind(template)
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

    /// Every override in the database, as `(tenant_id, host_id, ciphertext)`. For the
    /// startup rewrite only — request paths read one host's override, scoped to its tenant.
    pub async fn list_all(&self) -> Result<Vec<(i64, String, Vec<u8>)>> {
        let rows = sqlx::query("SELECT tenant_id, host_id, patch_encrypted FROM host_overrides")
            .fetch_all(&self.db.read)
            .await?;
        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("tenant_id"),
                    r.get::<String, _>("host_id"),
                    r.get::<Vec<u8>, _>("patch_encrypted"),
                )
            })
            .collect())
    }

    /// Replace just the ciphertext, leaving priority and authorship alone. Startup rewrite
    /// only — a real edit goes through [`Self::upsert`].
    pub async fn replace_ciphertext(
        &self,
        tenant_id: i64,
        host_id: &str,
        patch_encrypted: &[u8],
    ) -> Result<()> {
        sqlx::query(
            "UPDATE host_overrides SET patch_encrypted = ? WHERE tenant_id = ? AND host_id = ?",
        )
        .bind(patch_encrypted)
        .bind(tenant_id)
        .bind(host_id)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }

    pub async fn get(&self, tenant_id: i64, host_id: &str) -> Result<Option<StoredHostOverride>> {
        let row = sqlx::query(
            "SELECT host_id, patch_encrypted, priority, template FROM host_overrides
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
            template: r.get("template"),
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
        local_config_present: r
            .get::<Option<i64>, _>("local_config_present")
            .map(|v| v != 0),
        host_override_last: r
            .get::<Option<i64>, _>("host_override_last")
            .map(|v| v != 0),
        created_at: r.get("created_at"),
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

    /// What a presented client certificate is worth right now.
    ///
    /// Keyed on tenant and host as well as serial, and on the stored expiry, so the answer
    /// is "this certificate, issued to this host in this tenant, is live" rather than
    /// "some row somewhere has this serial and is not flagged". The tenant and host come
    /// from the verified chain, so a mismatch should be impossible — which is the reason
    /// to check it here rather than the reason not to.
    pub async fn standing(
        &self,
        tenant_id: i64,
        host_id: &str,
        serial: &str,
    ) -> Result<CertStanding> {
        // A host holds a handful of live certs at most, so one read for all of them beats
        // two aggregate subqueries over the same rows.
        //
        // Ordering is by rowid, not `issued_at`. `issued_at` comes from the certificate's
        // notBefore and has one-second granularity, so a renewal in the same second as the
        // certificate it replaces would tie and neither would ever be retired. Within one
        // host's rows rowid is insertion order exactly, and it cannot tie.
        let rows = sqlx::query(
            "SELECT rowid AS rid, serial FROM host_certs
             WHERE tenant_id = ? AND host_id = ? AND revoked_at IS NULL AND expires_at > ?",
        )
        .bind(tenant_id)
        .bind(host_id)
        .bind(now_unix())
        .fetch_all(&self.db.read)
        .await?;

        let mine = rows
            .iter()
            .find(|r| r.get::<String, _>("serial") == serial)
            .map(|r| r.get::<i64, _>("rid"));
        let Some(rid) = mine else {
            return Ok(CertStanding {
                active: false,
                superseded: 0,
            });
        };
        let superseded = rows.iter().filter(|r| r.get::<i64, _>("rid") < rid).count();
        Ok(CertStanding {
            active: true,
            superseded,
        })
    }

    /// Revoke every live certificate this host holds that was issued before `serial`.
    ///
    /// Called when the host presents `serial`, which is the point at which we know it
    /// actually received that certificate — a renewal whose response never arrived
    /// therefore costs the host nothing, and no grace window has to be guessed at.
    ///
    /// Strictly *older*, never "every other", because the caller is authenticated by the
    /// certificate it presents: if a thief replayed a stolen older key, "every other"
    /// would have it revoke the legitimate new one. Older means earlier rowid — see
    /// [`Self::standing`] for why not `issued_at`.
    pub async fn retire_superseded(
        &self,
        tenant_id: i64,
        host_id: &str,
        serial: &str,
    ) -> Result<u64> {
        let now = now_unix();
        let res = sqlx::query(
            "UPDATE host_certs SET revoked_at = ?
             WHERE tenant_id = ? AND host_id = ? AND revoked_at IS NULL AND expires_at > ?
               AND rowid < (SELECT rowid FROM host_certs
                            WHERE tenant_id = ? AND host_id = ? AND serial = ?)",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(host_id)
        .bind(now)
        .bind(tenant_id)
        .bind(host_id)
        .bind(serial)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected())
    }

    /// Revoke every live certificate a host holds. The operator-facing lever, for a host
    /// whose key is believed stolen; pair it with resetting the host to pending so it has
    /// a way back. See [`HostRepo::revoke_certs_and_reset_to_pending`].
    pub async fn revoke_all_for_host(&self, tenant_id: i64, host_id: &str) -> Result<u64> {
        let now = now_unix();
        let res = sqlx::query(
            "UPDATE host_certs SET revoked_at = ?
             WHERE tenant_id = ? AND host_id = ? AND revoked_at IS NULL",
        )
        .bind(now)
        .bind(tenant_id)
        .bind(host_id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected())
    }
}

/// The answer to "may this certificate act, and did it leave others behind?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertStanding {
    /// This serial is a live, unexpired, unrevoked certificate for this host.
    pub active: bool,
    /// Live certificates recorded for the same host before this one — what a renewal
    /// leaves behind. Non-zero means [`HostCertRepo::retire_superseded`] has work to do.
    pub superseded: usize,
}
