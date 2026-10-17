use anyhow::Result;
use fleet_core::api_key::ApiKey;
use fleet_core::session::Session;
use fleet_core::time::now_unix;
use fleet_core::user::{Role, User};
use sqlx::Row;

use crate::Db;

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
            blocked_at: None,
            is_platform_admin: false,
            created_at: now,
        })
    }

    pub async fn list(&self, tenant_id: i64) -> Result<Vec<User>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, email, role, blocked_at, is_platform_admin, created_at
             FROM users WHERE tenant_id = ? ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .fetch_all(&self.db.read)
        .await?;
        Ok(rows.into_iter().map(map_user).collect())
    }

    /// Look a user up by id alone, without knowing their tenant.
    ///
    /// The tenant-scoped `get` is what handlers should use — passing the caller's tenant_id
    /// is how cross-tenant reads are prevented by construction. This one exists for the
    /// platform console, where a user id is addressed from outside their tenant and the
    /// tenant is the *answer*, not an input.
    pub async fn get_any(&self, user_id: i64) -> Result<Option<User>> {
        let row = sqlx::query(
            "SELECT id, tenant_id, email, role, blocked_at, is_platform_admin, created_at
             FROM users WHERE id = ?",
        )
        .bind(user_id)
        .fetch_optional(&self.db.read)
        .await?;
        Ok(row.map(map_user))
    }

    /// Block or unblock an account.
    ///
    /// Blocking deletes the user's sessions in the same transaction. The session layer
    /// already refuses a blocked user on their next request, so this is belt and braces —
    /// but it also means an unblock hands back an account with no stale cookies attached,
    /// and the row count in `sessions` keeps meaning "people currently signed in".
    ///
    /// API keys are deliberately *not* deleted: blocking is reversible, and a block that
    /// silently destroyed a user's automation would not be. They stop working while the
    /// block is in force because the session layer resolves them through the owner's row.
    pub async fn set_blocked(&self, user_id: i64, blocked: bool) -> Result<bool> {
        let mut tx = self.db.write.begin().await?;
        let res = sqlx::query("UPDATE users SET blocked_at = ? WHERE id = ?")
            .bind(blocked.then(now_unix))
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
        if blocked {
            sqlx::query("DELETE FROM sessions WHERE user_id = ?")
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        }
        tx.commit().await?;
        Ok(res.rows_affected() == 1)
    }

    /// Grant or revoke the cross-tenant platform-admin flag.
    pub async fn set_platform_admin(&self, user_id: i64, is_admin: bool) -> Result<bool> {
        let res = sqlx::query("UPDATE users SET is_platform_admin = ? WHERE id = ?")
            .bind(i64::from(is_admin))
            .bind(user_id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected() == 1)
    }

    /// Grant the platform-admin flag to a user identified by address, if that address
    /// exists. Returns the user id when a row was promoted, `None` when the address is
    /// unknown or already had the flag — which is what `PLATFORM_ADMIN_EMAILS` bootstrapping
    /// needs to report at startup.
    pub async fn promote_platform_admin_by_email(&self, email: &str) -> Result<Option<i64>> {
        let id: Option<i64> = sqlx::query_scalar(
            "UPDATE users SET is_platform_admin = 1
              WHERE email = ? AND is_platform_admin = 0
              RETURNING id",
        )
        .bind(email)
        .fetch_optional(&self.db.write)
        .await?;
        Ok(id)
    }

    /// How many owners a tenant has. Used by the platform console to refuse the one deletion
    /// that would strand a tenant: removing its last owner.
    pub async fn count_owners(&self, tenant_id: i64) -> Result<i64> {
        let n: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE tenant_id = ? AND role = 'owner'")
                .bind(tenant_id)
                .fetch_one(&self.db.read)
                .await?;
        Ok(n)
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
        // Not tenant-scoped, because platform_settings is not: a platform admin can be the
        // last person to have flipped a switch that belongs to the whole install.
        sqlx::query(
            "UPDATE platform_settings SET updated_by_user = NULL WHERE updated_by_user = ?",
        )
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
            "SELECT id, tenant_id, email, role, blocked_at, is_platform_admin, created_at
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
            "SELECT id, tenant_id, email, role, blocked_at, is_platform_admin, created_at
             FROM users WHERE email = ? LIMIT 1",
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
        blocked_at: r.get("blocked_at"),
        is_platform_admin: r.get::<i64, _>("is_platform_admin") != 0,
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
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        &self,
        tenant_id: i64,
        user_id: i64,
        name: &str,
        token_hash: &str,
        token_prefix: &str,
        expires_at: Option<i64>,
    ) -> Result<ApiKey> {
        let id = ulid::Ulid::generate().to_string();
        let now = now_unix();
        sqlx::query(
            "INSERT INTO api_keys
             (id, tenant_id, user_id, name, token_hash, token_prefix, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(user_id)
        .bind(name)
        .bind(token_hash)
        .bind(token_prefix)
        .bind(now)
        .bind(expires_at)
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
            expires_at,
        })
    }

    pub async fn list_for_user(&self, tenant_id: i64, user_id: i64) -> Result<Vec<ApiKey>> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, user_id, name, token_prefix, created_at, last_used_at,
                    expires_at
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
            "SELECT id, tenant_id, user_id, name, token_prefix, created_at, last_used_at,
                    expires_at
             FROM api_keys WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > ?)",
        )
        .bind(token_hash)
        .bind(now_unix())
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
        expires_at: r.get("expires_at"),
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

    /// Fetch a session by token hash, refreshing `last_used_at`.
    ///
    /// Returns None if missing, past its absolute lifetime, or idle for longer than
    /// `idle_ttl_seconds`. The idle bound is the one that matters for a console left open
    /// on an unattended machine: an absolute lifetime alone means a session taken on day
    /// one is still good on day six regardless of whether anyone has touched it. Both
    /// conditions are in the statement that refreshes the timestamp, so there is no window
    /// between checking and extending.
    pub async fn touch(&self, id_hash: &str, idle_ttl_seconds: i64) -> Result<Option<Session>> {
        let now = now_unix();
        let row = sqlx::query(
            "UPDATE sessions
             SET last_used_at = ?
             WHERE id = ? AND expires_at > ? AND last_used_at > ?
             RETURNING id, tenant_id, user_id, expires_at, last_used_at, created_at",
        )
        .bind(now)
        .bind(id_hash)
        .bind(now)
        .bind(now - idle_ttl_seconds)
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

    /// Sign a user out of every session, including the one making the request.
    ///
    /// Backs "sign out everywhere", which is what someone reaches for when they think a
    /// session has been taken — and until now the only way to get it was for an admin to
    /// block or delete the account.
    pub async fn delete_for_user(&self, tenant_id: i64, user_id: i64) -> Result<u64> {
        let res = sqlx::query("DELETE FROM sessions WHERE tenant_id = ? AND user_id = ?")
            .bind(tenant_id)
            .bind(user_id)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }

    /// Drop rows past their absolute lifetime, or idle past `idle_ttl_seconds`.
    ///
    /// Neither is required for correctness — `touch` refuses both — but a row that can
    /// never authenticate anything again is a stored credential hash with no purpose, and
    /// this table only ever grew.
    pub async fn delete_expired(&self, idle_ttl_seconds: i64) -> Result<u64> {
        let now = now_unix();
        let res = sqlx::query("DELETE FROM sessions WHERE expires_at < ? OR last_used_at < ?")
            .bind(now)
            .bind(now - idle_ttl_seconds)
            .execute(&self.db.write)
            .await?;
        Ok(res.rows_affected())
    }
}
