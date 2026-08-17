use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_storage::{Db, MagicLinkRepo, TenantRepo, UserRepo};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

// Helper struct to keep the server task alive for the duration of a test.
struct TestServer {
    base_url: String,
    _tempdir: TempDir,
    handle: tokio::task::JoinHandle<()>,
    db: Db,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start() -> TestServer {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    // Build state by mirroring main.rs setup, but pointed at the temp DB.
    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let cfg = test_config(db_path);
    let (mtls_cert_pem, mtls_key_pem) =
        fleet_server::mtls::generate_self_signed_server("127.0.0.1").unwrap();
    let email = fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap();
    let turnstile =
        fleet_server::auth::turnstile::Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget);
    let trust_store =
        fleet_server::mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem)
            .await
            .unwrap();

    let state = fleet_server::AppState {
        db: db.clone(),
        config: cfg,
        email,
        turnstile,
        rate_limits,
        agent_limits: fleet_server::agent_limits::AgentRateLimits::new(),
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::default(),
        trust_store,
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let app = fleet_server::router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    // Wait briefly until the listener accepts.
    for _ in 0..50 {
        if reqwest::get(format!("{base_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    TestServer {
        base_url,
        _tempdir: dir,
        handle,
        db,
    }
}

fn test_config(db_path: PathBuf) -> fleet_server::config::Config {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let key_b64 = MasterKey::generate_b64();
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();
    fleet_server::config::Config {
        listen: "127.0.0.1:0".into(),
        listen_https: "127.0.0.1:0".into(),
        listen_mtls: "127.0.0.1:0".into(),
        agent_mtls_url: "https://127.0.0.1".into(),
        acme: None,
        database_path: db_path,
        base_url: "http://localhost".into(),
        on_prem: false,
        on_prem_admin_email: None,
        on_prem_admin_password: None,
        platform_admin_emails: Vec::new(),
        magic_link_ttl_secs: 900,
        session_ttl_secs: 3600,
        bootstrap_ttl_secs: 3600,
        host_lost_after_secs: 172_800,
        client_cert_lifetime_days: 90,
        cookie_secure: false,
        daily_email_budget: 1_000_000,
        smtp: None,
        turnstile_secret: None,
        master_key,
        bootstrap_jwt_secret,
    }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let d = h.finalize();
    d.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn signup_creates_tenant_user_and_magic_link() {
    let s = start().await;
    let c = client();

    let res = c
        .post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "tenant_slug": "acme",
            "tenant_name": "Acme",
            "turnstile_token": "",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    let tenants_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    let users_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    let links_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(tenants_count, 1);
    assert_eq!(users_count, 1);
    assert_eq!(links_count, 1);
}

#[tokio::test]
async fn send_link_unknown_email_returns_204_with_no_link() {
    let s = start().await;
    let c = client();

    let res = c
        .post(format!("{}/api/auth/send-link", s.base_url))
        .json(&serde_json::json!({ "email": "ghost@nowhere" }))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 204);

    let links_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(links_count, 0);
}

#[tokio::test]
async fn exchange_burns_link_sets_cookie_and_me_works() {
    let s = start().await;
    let c = client();

    let tenants = TenantRepo::new(&s.db);
    let users = UserRepo::new(&s.db);
    let links = MagicLinkRepo::new(&s.db);
    let t = tenants.create("acme", "Acme", "free", None).await.unwrap();
    let u = users
        .create(t.id, "alice@example.com", fleet_core::user::Role::Owner)
        .await
        .unwrap();
    let token = "test-token-abcdefghij";
    let hash = hash_token(token);
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();

    let res = c
        .get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 303);

    let me = c
        .get(format!("{}/api/me", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(me.status(), 200);
    let body: serde_json::Value = me.json().await.unwrap();
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["tenant_slug"], "acme");

    // Replay must fail
    let replay = c
        .get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(replay.status(), 401);

    // Logout
    let lo = c
        .post(format!("{}/api/auth/logout", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(lo.status(), 204);

    let me2 = c
        .get(format!("{}/api/me", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(me2.status(), 401);
}

#[tokio::test]
async fn exchange_expired_token_rejected() {
    let s = start().await;
    let c = client();

    let tenants = TenantRepo::new(&s.db);
    let users = UserRepo::new(&s.db);
    let links = MagicLinkRepo::new(&s.db);
    let t = tenants.create("acme", "Acme", "free", None).await.unwrap();
    let u = users
        .create(t.id, "alice@example.com", fleet_core::user::Role::Owner)
        .await
        .unwrap();
    let token = "expired-xxxxxxxxx";
    let hash = hash_token(token);
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() - 5)
        .await
        .unwrap();

    let res = c
        .get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 401);
}
