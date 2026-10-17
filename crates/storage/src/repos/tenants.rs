use anyhow::Result;
use fleet_core::tenant::Tenant;
use fleet_core::time::now_unix;
use sqlx::{AssertSqlSafe, Row};

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

    /// Every tenant on the estate, with the numbers the platform console shows beside them.
    pub async fn list_with_counts(&self) -> Result<Vec<TenantSummary>> {
        self.summaries(None).await
    }

    /// One tenant, counted the same way as `list_with_counts` — so a console that has just
    /// edited a subscription can render the result without the counts arriving as zeros.
    pub async fn get_with_counts(&self, tenant_id: i64) -> Result<Option<TenantSummary>> {
        Ok(self.summaries(Some(tenant_id)).await?.into_iter().next())
    }

    /// The counts are correlated subqueries rather than a second round trip per tenant: the
    /// console lists the whole estate, and an N+1 there would grow with the customer base.
    ///
    /// `host_count` deliberately matches what the tier limit actually counts
    /// (`HostRepo::count_active`) — enrolled hosts plus pending ones from the last 24h — so
    /// the "42 / 50 hosts" the console shows is the same 42 that will refuse the 51st.
    ///
    /// `local_config_host_count` needs no such window: only a host that has enrolled and
    /// reported can have the flag set at all, so counting the flag alone can never exceed it.
    async fn summaries(&self, only_tenant: Option<i64>) -> Result<Vec<TenantSummary>> {
        let sql = format!(
            "SELECT t.id, t.slug, t.name, t.tier, t.tier_overrides_json, t.trial_expires_at,
                    t.config_version, t.created_at,
                    (SELECT COUNT(*) FROM users u WHERE u.tenant_id = t.id)
                        AS user_count,
                    (SELECT COUNT(*) FROM users u
                      WHERE u.tenant_id = t.id AND u.blocked_at IS NOT NULL)
                        AS blocked_user_count,
                    (SELECT COUNT(*) FROM hosts h
                      WHERE h.tenant_id = t.id
                        AND (h.enrolled_at IS NOT NULL
                             OR (h.enrolled_at IS NULL AND h.created_at > ?)))
                        AS host_count,
                    (SELECT COUNT(*) FROM hosts h
                      WHERE h.tenant_id = t.id AND h.local_config_present = 1)
                        AS local_config_host_count
             FROM tenants t
             {}
             ORDER BY t.created_at DESC",
            if only_tenant.is_some() {
                "WHERE t.id = ?"
            } else {
                ""
            }
        );
        let mut q = sqlx::query(AssertSqlSafe(sql)).bind(now_unix() - 86_400);
        if let Some(id) = only_tenant {
            q = q.bind(id);
        }
        let rows = q.fetch_all(&self.db.read).await?;

        Ok(rows
            .into_iter()
            .map(|r| TenantSummary {
                user_count: r.get("user_count"),
                blocked_user_count: r.get("blocked_user_count"),
                host_count: r.get("host_count"),
                local_config_host_count: r.get("local_config_host_count"),
                tenant: map_tenant(r),
            })
            .collect())
    }

    /// Replace a tenant's subscription wholesale: named tier, trial deadline, and the
    /// numeric overrides sitting on top of it.
    ///
    /// Every field is authoritative — `None` clears rather than preserves. The console edits
    /// all three in one form, and under COALESCE semantics "this tenant has paid, drop the
    /// trial" would be indistinguishable from "leave the trial alone".
    ///
    /// The caller validates `tier` against `fleet_core::tier::lookup` and `overrides_json`
    /// against `TierOverrides`; this layer only writes what it is given.
    pub async fn update_subscription(
        &self,
        tenant_id: i64,
        tier: &str,
        trial_expires_at: Option<i64>,
        overrides_json: Option<&str>,
    ) -> Result<bool> {
        let res = sqlx::query(
            "UPDATE tenants
                SET tier = ?, trial_expires_at = ?, tier_overrides_json = ?
              WHERE id = ?",
        )
        .bind(tier)
        .bind(trial_expires_at)
        .bind(overrides_json)
        .bind(tenant_id)
        .execute(&self.db.write)
        .await?;
        Ok(res.rows_affected() > 0)
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

/// A tenant plus the counts the platform console shows next to it. Built by
/// `TenantRepo::list_with_counts`.
#[derive(Debug, Clone)]
pub struct TenantSummary {
    pub tenant: Tenant,
    pub user_count: i64,
    pub blocked_user_count: i64,
    pub host_count: i64,
    /// Hosts that have reported configuration of their own outranking the fleet's — i.e.
    /// how much of this tenant is only partly centrally managed.
    pub local_config_host_count: i64,
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

    /// Replace both encrypted columns for one tenant. Only the startup rewrite that binds
    /// legacy ciphertexts to their purpose has any reason to call this.
    pub async fn replace_encrypted_keys(
        &self,
        tenant_id: i64,
        ca_key_encrypted: &[u8],
        bundle_signing_key_encrypted: &[u8],
    ) -> Result<()> {
        sqlx::query(
            "UPDATE tenant_secrets
             SET ca_key_encrypted = ?, bundle_signing_key_encrypted = ?
             WHERE tenant_id = ?",
        )
        .bind(ca_key_encrypted)
        .bind(bundle_signing_key_encrypted)
        .bind(tenant_id)
        .execute(&self.db.write)
        .await?;
        Ok(())
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

/// The tenant's bundle-encryption-key *fingerprint*. The key itself is client-side only
/// (operator password manager + agents); the server keeps just enough to tell the UI and
/// agents which key a bundle was encrypted with.
pub struct TenantBundleKeysRepo<'a> {
    db: &'a Db,
}

impl<'a> TenantBundleKeysRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn get(&self, tenant_id: i64) -> Result<Option<String>> {
        let fp: Option<String> =
            sqlx::query_scalar("SELECT fingerprint FROM tenant_bundle_keys WHERE tenant_id = ?")
                .bind(tenant_id)
                .fetch_optional(&self.db.read)
                .await?;
        Ok(fp)
    }

    pub async fn set(
        &self,
        tenant_id: i64,
        fingerprint: &str,
        created_by_user: Option<i64>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO tenant_bundle_keys (tenant_id, fingerprint, created_at, created_by_user)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(tenant_id) DO UPDATE SET
               fingerprint = excluded.fingerprint,
               created_at = excluded.created_at,
               created_by_user = excluded.created_by_user",
        )
        .bind(tenant_id)
        .bind(fingerprint)
        .bind(now_unix())
        .bind(created_by_user)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }
}

/// Process-wide switches that belong to no tenant.
///
/// Key/value on purpose: these are rare, unrelated, and read at most once per request that
/// cares. A typed column per switch would mean a migration for each one and a struct that
/// every caller has to fetch in full. Values are strings; the server owns their meaning
/// (see `fleet_server::admin::platform::settings`), including what an absent key defaults to.
pub struct PlatformSettingsRepo<'a> {
    db: &'a Db,
}

impl<'a> PlatformSettingsRepo<'a> {
    pub fn new(db: &'a Db) -> Self {
        Self { db }
    }

    pub async fn get(&self, key: &str) -> Result<Option<String>> {
        let value: Option<String> =
            sqlx::query_scalar("SELECT value FROM platform_settings WHERE key = ?")
                .bind(key)
                .fetch_optional(&self.db.read)
                .await?;
        Ok(value)
    }

    pub async fn set(&self, key: &str, value: &str, updated_by_user: Option<i64>) -> Result<()> {
        sqlx::query(
            "INSERT INTO platform_settings (key, value, updated_at, updated_by_user)
             VALUES (?, ?, ?, ?)
             ON CONFLICT(key) DO UPDATE SET
               value = excluded.value,
               updated_at = excluded.updated_at,
               updated_by_user = excluded.updated_by_user",
        )
        .bind(key)
        .bind(value)
        .bind(now_unix())
        .bind(updated_by_user)
        .execute(&self.db.write)
        .await?;
        Ok(())
    }
}
