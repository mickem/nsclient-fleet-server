use sqlx::SqlitePool;

pub async fn run_migrations(write: &SqlitePool) -> anyhow::Result<i64> {
    sqlx::migrate!("../../migrations").run(write).await?;

    let version: Option<i64> =
        sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success = 1")
            .fetch_one(write)
            .await?;

    Ok(version.unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use sqlx::migrate::Migrator;
    use std::borrow::Cow;

    /// 0006 rebuilds the `users` table, which four other tables reference. On a fresh
    /// database that is trivially safe — there is nothing to orphan — so the ordinary test
    /// suite never exercises the case that can actually fail.
    ///
    /// This applies 0001..0005, populates every table that references `users(id)`, and only
    /// then lets 0006 run. If that migration stops clearing and restoring those references,
    /// `DROP TABLE users` reports a constraint violation here rather than on the operator's
    /// live database during an upgrade.
    #[tokio::test]
    async fn migration_0006_rebuilds_users_without_orphaning_references() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");
        let db = crate::pool::open(path.to_str().unwrap()).await.unwrap();

        let full = sqlx::migrate!("../../migrations");
        let before_0006 = Migrator {
            migrations: Cow::Owned(
                full.migrations
                    .iter()
                    .filter(|m| m.version < 6)
                    .cloned()
                    .collect::<Vec<_>>(),
            ),
            ignore_missing: full.ignore_missing,
            locking: full.locking,
            no_tx: full.no_tx,
        };
        before_0006.run(&db.write).await.unwrap();

        // One row in each table that has a REFERENCES users(id) clause, plus an 'owner' and
        // a legacy 'member' to prove the role mapping.
        sqlx::query("INSERT INTO tenants (id, slug, name, tier, created_at) VALUES (1,'acme','Acme','free',0)")
            .execute(&db.write).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, tenant_id, email, role, created_at)
             VALUES (1,1,'owner@example.com','owner',0), (2,1,'member@example.com','member',0)",
        )
        .execute(&db.write)
        .await
        .unwrap();
        sqlx::query("INSERT INTO sessions (id, tenant_id, user_id, expires_at, last_used_at, created_at) VALUES ('s',1,2,9999999999,0,0)")
            .execute(&db.write).await.unwrap();
        sqlx::query("INSERT INTO magic_links (token_hash, tenant_id, user_id, expires_at, created_at) VALUES ('h',1,2,9999999999,0)")
            .execute(&db.write).await.unwrap();
        sqlx::query("INSERT INTO audit_log (tenant_id, user_id, action, target_type, target_id, ts) VALUES (1,2,'host.created','host','x',0)")
            .execute(&db.write).await.unwrap();
        sqlx::query("INSERT INTO hosts (id, tenant_id, created_at) VALUES ('h1',1,0)")
            .execute(&db.write)
            .await
            .unwrap();
        sqlx::query("INSERT INTO host_overrides (tenant_id, host_id, patch_encrypted, updated_at, updated_by_user) VALUES (1,'h1',X'00',0,2)")
            .execute(&db.write).await.unwrap();

        full.run(&db.write).await.expect("0006 must apply cleanly");

        // Roles mapped: owner kept, legacy 'member' promoted rather than silently demoted.
        let roles: Vec<(i64, String)> = sqlx::query_as("SELECT id, role FROM users ORDER BY id")
            .fetch_all(&db.read)
            .await
            .unwrap();
        assert_eq!(
            roles,
            vec![(1, "owner".to_string()), (2, "admin".to_string())]
        );

        // The new CHECK is in force…
        assert!(
            sqlx::query("UPDATE users SET role = 'member' WHERE id = 2")
                .execute(&db.write)
                .await
                .is_err(),
            "the old vocabulary must no longer be accepted"
        );
        sqlx::query("UPDATE users SET role = 'add_hosts' WHERE id = 2")
            .execute(&db.write)
            .await
            .expect("new roles must be accepted");

        // Attribution survived the rebuild — these are parked in temp tables and written
        // back, and losing them would quietly rewrite the audit trail.
        let audit_user: Option<i64> = sqlx::query_scalar("SELECT user_id FROM audit_log LIMIT 1")
            .fetch_one(&db.read)
            .await
            .unwrap();
        assert_eq!(audit_user, Some(2), "audit attribution must be restored");
        let ovr_user: Option<i64> =
            sqlx::query_scalar("SELECT updated_by_user FROM host_overrides LIMIT 1")
                .fetch_one(&db.read)
                .await
                .unwrap();
        assert_eq!(ovr_user, Some(2), "override attribution must be restored");

        // Sessions and magic links are deliberately cleared: everyone signs in again.
        let sessions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions")
            .fetch_one(&db.read)
            .await
            .unwrap();
        assert_eq!(sessions, 0);

        // …and nothing was orphaned: every reference still resolves, and the FK clauses
        // still point at a real table (an INSERT proves the constraint is live, not dangling).
        let violations = sqlx::query("PRAGMA foreign_key_check")
            .fetch_all(&db.read)
            .await
            .unwrap();
        assert!(violations.is_empty(), "foreign_key_check must be clean");
        assert!(
            sqlx::query("INSERT INTO sessions (id, tenant_id, user_id, expires_at, last_used_at, created_at) VALUES ('s2',1,404,0,0,0)")
                .execute(&db.write)
                .await
                .is_err(),
            "sessions.user_id must still be enforced against the rebuilt table"
        );
    }
}
