//! Phase 7 — multi-tenancy hardening. Comprehensive cross-tenant isolation probes plus
//! trial-expiry behavior.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_storage::Db;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    _tempdir: TempDir,
    handles: Vec<tokio::task::JoinHandle<()>>,
    db: Db,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

async fn start() -> TestServer {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mtls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let mtls_addr = mtls_listener.local_addr().unwrap();
    let base_url = format!("http://{http_addr}");

    let key_b64 = MasterKey::generate_b64();
    std::env::set_var("MASTER_KEY", &key_b64);
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();

    let cfg = fleet_server::config::Config {
        listen: format!("127.0.0.1:{}", http_addr.port()),
        listen_https: "127.0.0.1:0".into(),
        listen_mtls: format!("127.0.0.1:{}", mtls_addr.port()),
        agent_mtls_url: format!("https://127.0.0.1:{}", mtls_addr.port()),
        acme: None,
        database_path: PathBuf::from(&db_path),
        base_url: base_url.clone(),
        on_prem: false,
        on_prem_admin_email: None,
        on_prem_admin_password: None,
        magic_link_ttl_secs: 900,
        session_ttl_secs: 3600,
        bootstrap_ttl_secs: 3600,
        client_cert_lifetime_days: 90,
        cookie_secure: false,
        daily_email_budget: 1_000_000,
        smtp: None,
        turnstile_secret: None,
        master_key,
        bootstrap_jwt_secret,
    };

    let (mtls_cert_pem, mtls_key_pem) =
        fleet_server::mtls::generate_self_signed_server("127.0.0.1").unwrap();
    let email = fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap();
    let turnstile =
        fleet_server::auth::turnstile::Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget);
    let agent_limits = fleet_server::agent_limits::AgentRateLimits::new();
    let trust_store =
        fleet_server::mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem)
            .await
            .unwrap();

    let state = fleet_server::AppState {
        db: db.clone(),
        config: cfg.clone(),
        email,
        turnstile,
        rate_limits,
        agent_limits,
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::default(),
        trust_store: trust_store.clone(),
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    let mtls_state = state.clone();
    let mtls_handle = tokio::spawn(async move {
        let r = fleet_server::mtls_router(mtls_state.clone());
        let _ = fleet_server::mtls::serve_on(mtls_listener, mtls_state.trust_store, r).await;
    });

    let app = fleet_server::router(state);
    let http_handle = tokio::spawn(async move {
        let _ = axum::serve(
            http_listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    for _ in 0..50 {
        if reqwest::get(format!("{base_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    TestServer {
        base_url,
        _tempdir: dir,
        handles: vec![http_handle, mtls_handle],
        db,
    }
}

fn fresh_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn signup_and_login(s: &TestServer, c: &reqwest::Client, slug: &str, email: &str) {
    c.post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": email,
            "tenant_slug": slug,
            "tenant_name": slug.to_uppercase(),
            "turnstile_token": "",
        }))
        .send()
        .await
        .unwrap();

    let tenants = fleet_storage::TenantRepo::new(&s.db);
    let users = fleet_storage::UserRepo::new(&s.db);
    let links = fleet_storage::MagicLinkRepo::new(&s.db);
    let t = tenants.get_by_slug(slug).await.unwrap().unwrap();
    let u = users.find_by_email(email).await.unwrap().unwrap();
    let token = format!("magic-{slug}-XXXXXXXX");
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let hash: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();
    c.get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
}

struct Provisioned {
    host_id: String,
    group_id: String,
    bundle_id: String,
}

async fn provision(s: &TestServer, c: &reqwest::Client) -> Provisioned {
    // Host
    let host = c
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let host_id = host["host_id"].as_str().unwrap().to_string();

    // Group
    let group = c
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "g1",
            "selector": { "clauses": [] }
        }))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap().to_string();

    // Bundle
    let form = reqwest::multipart::Form::new()
        .text("name", "b1")
        .text("version", "1.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(b"opaque-bytes".to_vec())
                .file_name("b.zip")
                .mime_str("application/zip")
                .unwrap(),
        );
    let bundle: serde_json::Value = c
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bundle_id = bundle["id"].as_str().unwrap().to_string();

    Provisioned {
        host_id,
        group_id,
        bundle_id,
    }
}

#[tokio::test]
async fn cross_tenant_access_is_denied_everywhere() {
    let s = start().await;
    let ca = fresh_client();
    let cb = fresh_client();
    signup_and_login(&s, &ca, "alpha", "a@example.com").await;
    signup_and_login(&s, &cb, "beta", "b@example.com").await;
    let pa = provision(&s, &ca).await;
    let pb = provision(&s, &cb).await;

    // Sanity: each session can read its own
    let own = cb
        .get(format!("{}/api/hosts/{}", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), 200);

    // -- Probes from A's session against B's resources -------------------------------
    // host detail
    let r = ca
        .get(format!("{}/api/hosts/{}", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "detail: A must not see B's host");

    // tag write
    let r = ca
        .put(format!("{}/api/hosts/{}/tags/role", s.base_url, pb.host_id))
        .json(&serde_json::json!({"value": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "tag put: A must not target B's host");

    // tag delete
    let r = ca
        .delete(format!("{}/api/hosts/{}/tags/role", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "tag delete");

    // override write
    let r = ca
        .put(format!("{}/api/hosts/{}/override", s.base_url, pb.host_id))
        .json(&serde_json::json!({"patch": {"x": 1}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "override put: A must not target B's host");

    // override delete
    let r = ca
        .delete(format!("{}/api/hosts/{}/override", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "override delete");

    // group patch
    let r = ca
        .patch(format!("{}/api/groups/{}", s.base_url, pb.group_id))
        .json(&serde_json::json!({"name": "hijacked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "group patch");

    // group delete
    let r = ca
        .delete(format!("{}/api/groups/{}", s.base_url, pb.group_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "group delete");

    // assign A's bundle to B's group (NOT FOUND because the group isn't A's)
    let r = ca
        .post(format!("{}/api/groups/{}/bundles", s.base_url, pb.group_id))
        .json(&serde_json::json!({"bundle_id": pa.bundle_id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "cross-group assignment");

    // assign B's bundle to A's group (NOT FOUND because the bundle isn't A's)
    let r = ca
        .post(format!("{}/api/groups/{}/bundles", s.base_url, pa.group_id))
        .json(&serde_json::json!({"bundle_id": pb.bundle_id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "cross-bundle assignment");

    // Listing groups from A's session must not include B's group
    let groups: Vec<serde_json::Value> = ca
        .get(format!("{}/api/groups", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = groups.iter().filter_map(|g| g["id"].as_str()).collect();
    assert!(ids.contains(&pa.group_id.as_str()));
    assert!(!ids.contains(&pb.group_id.as_str()));

    // Listing bundles
    let bundles: Vec<serde_json::Value> = ca
        .get(format!("{}/api/bundles", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bids: Vec<&str> = bundles.iter().filter_map(|b| b["id"].as_str()).collect();
    assert!(bids.contains(&pa.bundle_id.as_str()));
    assert!(!bids.contains(&pb.bundle_id.as_str()));
}

#[tokio::test]
async fn expired_trial_returns_402_except_allowlisted() {
    let s = start().await;
    let c = fresh_client();
    signup_and_login(&s, &c, "tex", "t@example.com").await;

    // Force expiry directly in the DB
    sqlx::query("UPDATE tenants SET trial_expires_at = ? WHERE slug = 'tex'")
        .bind(fleet_core::time::now_unix() - 3600)
        .execute(&s.db.write)
        .await
        .unwrap();

    // /api/me works (allowlisted) and reports trial_expired: true
    let me_resp = c
        .get(format!("{}/api/me", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(me_resp.status(), 200);
    let me: serde_json::Value = me_resp.json().await.unwrap();
    assert_eq!(me["trial_expired"], true);

    // Other API routes return 402
    let r = c
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 402);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"], "trial_expired");

    let r = c
        .get(format!("{}/api/groups", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 402);

    // Logout still works (allowlisted)
    let r = c
        .post(format!("{}/api/auth/logout", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[tokio::test]
async fn paid_or_unlimited_tenants_unaffected_by_expiry_check() {
    let s = start().await;
    let c = fresh_client();
    signup_and_login(&s, &c, "paid", "p@example.com").await;

    // No trial_expires_at → never expires (e.g. paid customers, on-prem)
    sqlx::query("UPDATE tenants SET trial_expires_at = NULL WHERE slug = 'paid'")
        .execute(&s.db.write)
        .await
        .unwrap();

    let r = c
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
