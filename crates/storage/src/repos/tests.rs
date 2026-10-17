use super::*;
use crate::{open, run_migrations, Db};
use fleet_core::time::now_unix;
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

    let touched = sessions.touch("session_hash", 3600).await.unwrap().unwrap();
    assert_eq!(touched.user_id, u.id);

    // Idle for longer than the allowance is as good as gone, even though the absolute
    // lifetime has not run out.
    assert!(
        sessions.touch("session_hash", 0).await.unwrap().is_none(),
        "an idle session must not authenticate"
    );

    sessions.delete("session_hash").await.unwrap();
    assert!(sessions
        .touch("session_hash", 3600)
        .await
        .unwrap()
        .is_none());
}
