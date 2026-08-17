//! Phase 5 end-to-end: tag a host, define a group, upload a bundle, assign it, agent picks
//! it up + verifies. Plus host override (encrypted secret never logged).

use std::collections::BTreeMap;
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
    agent_limits: fleet_server::agent_limits::AgentRateLimits,
    cookie_jar: reqwest::Client,
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
    let bundle_dir = dir.path().join("bundles");

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
    let bundle_store: Arc<dyn fleet_server::bundles::BundleStore> =
        Arc::new(fleet_server::bundles::LocalBundleStore::new(bundle_dir));

    let agent_limits_handle = agent_limits.clone();
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
        bundle_store,
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
        agent_limits: agent_limits_handle,
        cookie_jar: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

async fn signup_login(s: &TestServer, slug: &str, email: &str) {
    s.cookie_jar
        .post(format!("{}/api/auth/signup", s.base_url))
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
    s.cookie_jar
        .get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
}

async fn enroll_a_host(s: &TestServer) -> (fleet_agent_sim::EnrolledAgent, String) {
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let token = body["bootstrap_token"].as_str().unwrap().to_string();
    let host_id = body["host_id"].as_str().unwrap().to_string();

    let mut last = String::new();
    for _ in 0..20 {
        match fleet_agent_sim::enroll(&s.base_url, &token, Some("alpha"), Some("linux")).await {
            Ok(a) => return (a, host_id),
            Err(e) => last = format!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("enroll never succeeded: {last}");
}

#[tokio::test]
async fn end_to_end_tag_group_bundle_assign_and_fetch() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let (agent, host_id) = enroll_a_host(&s).await;

    // 1. Operator creates a group selecting hosts where role = sql_server
    let g = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "sql-servers",
            "selector": { "clauses": [{"op": "eq", "key": "role", "value": "sql_server"}] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(g.status(), 201);
    let group: serde_json::Value = g.json().await.unwrap();
    let group_id = group["id"].as_str().unwrap().to_string();

    // 2. Operator uploads a bundle (raw bytes — server treats it opaquely for delivery)
    let bundle_bytes: Vec<u8> = b"fake-zip-contents-for-test".to_vec();
    let form = reqwest::multipart::Form::new()
        .text("name", "sql-monitoring")
        .text("version", "1.2.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(bundle_bytes.clone())
                .file_name("bundle.zip")
                .mime_str("application/zip")
                .unwrap(),
        );
    let bres = s
        .cookie_jar
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(bres.status(), 200, "upload: {:?}", bres.text().await);
    let bundle: serde_json::Value = bres.json().await.unwrap();
    let bundle_id = bundle["id"].as_str().unwrap().to_string();
    let expected_sha = bundle["sha256"].as_str().unwrap().to_string();
    let signature = bundle["signature"].as_str().unwrap().to_string();

    // 3. Assign bundle to group
    let a = s
        .cookie_jar
        .post(format!("{}/api/groups/{}/bundles", s.base_url, group_id))
        .json(&serde_json::json!({"bundle_id": bundle_id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), 204);

    // 4. Host has no matching tags yet → desired-state must have empty bundle list
    s.agent_limits.forget_last_poll(&host_id);
    let ds = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(ds.bundles.len(), 0, "no role tag → no matching bundle");

    // 5. Agent reports `role=sql_server` via state-report → tag added
    let mut tags = BTreeMap::new();
    tags.insert("role".into(), "sql_server".into());
    agent.report_state(None, tags).await.unwrap();

    // 6. Next poll → bundle now matches
    s.agent_limits.forget_last_poll(&host_id);
    let ds2 = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(ds2.bundles.len(), 1, "role match should pull in bundle");

    // 7. Agent downloads the bundle and verifies sha256 + signature
    let downloaded = agent
        .fetch_bundle(&bundle_id, &expected_sha, &signature)
        .await
        .unwrap();
    assert_eq!(downloaded, bundle_bytes);
}

#[tokio::test]
async fn manual_tag_endpoint_bumps_config_version() {
    let s = start().await;
    signup_login(&s, "beta", "bob@example.com").await;
    let (_agent, host_id) = enroll_a_host(&s).await;

    let v_before: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();

    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/env", s.base_url, host_id))
        .json(&serde_json::json!({"value": "prod"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    let v_after: i64 = sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert!(
        v_after > v_before,
        "manual tag PUT must bump config_version"
    );

    // Re-PUT with same value: changed=false, no bump
    let r2 = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/env", s.base_url, host_id))
        .json(&serde_json::json!({"value": "prod"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status(), 204);
    let v_after2: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(v_after2, v_after, "no-op tag PUT must not bump");
}

#[tokio::test]
async fn host_override_is_encrypted_at_rest() {
    let s = start().await;
    signup_login(&s, "gamma", "carol@example.com").await;
    let (_agent, host_id) = enroll_a_host(&s).await;

    let secret = "super-secret-db-password-123";
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({
            "patch": { "db": { "password": secret } },
            "priority": 1500
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // The raw blob in the DB must NOT contain the secret in plaintext.
    let raw: Vec<u8> =
        sqlx::query_scalar("SELECT patch_encrypted FROM host_overrides WHERE host_id = ?")
            .bind(&host_id)
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    let needle = secret.as_bytes();
    let leaks = raw.windows(needle.len()).any(|w| w == needle);
    assert!(!leaks, "secret leaked into encrypted blob");

    // After delete, override row gone.
    let d = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(d.status(), 204);
}

#[tokio::test]
async fn group_with_no_matching_hosts_yields_empty_state() {
    let s = start().await;
    signup_login(&s, "delta", "dave@example.com").await;
    let (agent, _host_id) = enroll_a_host(&s).await;

    // Create a group that won't match (host has no role=ghost tag)
    s.cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "ghost",
            "selector": { "clauses": [{"op": "eq", "key": "role", "value": "ghost"}] }
        }))
        .send()
        .await
        .unwrap();

    let ds = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(ds.bundles.len(), 0);
    assert_eq!(ds.merged_config_json, serde_json::json!({}));
}

#[tokio::test]
async fn bad_selector_rejected() {
    let s = start().await;
    signup_login(&s, "eps", "e@example.com").await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "bad",
            "selector": { "clauses": [{"op": "regex", "key": "k", "value": "v"}] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn compose_edit_next_version_preserves_scripts() {
    let s = start().await;
    signup_login(&s, "editor", "editor@example.com").await;

    // 1. Compose a fresh bundle from JSON config (the INI editor's save path).
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({
            "name": "web-config",
            "version": "1.0.0",
            "config_json": { "settings": { "log": { "level": "debug" } } },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "compose: {:?}", r.text().await);
    let created: serde_json::Value = r.json().await.unwrap();
    let first_id = created["id"].as_str().unwrap().to_string();

    // 2. Read it back for editing: config round-trips, no scripts.
    let cfg: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/bundles/{}/config", s.base_url, first_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cfg["config_json"],
        serde_json::json!({ "settings": { "log": { "level": "debug" } } })
    );
    assert_eq!(cfg["scripts"].as_array().unwrap().len(), 0);

    // 3. Upload a hand-built zip that carries a script.
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        use std::io::Write;
        let mut w = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default();
        w.start_file("config.json", opts).unwrap();
        w.write_all(br#"{ "settings": { "old": "1" } }"#).unwrap();
        w.start_file("scripts/check_disk.ps1", opts).unwrap();
        w.write_all(b"Write-Output 'ok'").unwrap();
        w.finish().unwrap();
    }
    let form = reqwest::multipart::Form::new()
        .text("name", "scripted")
        .text("version", "1.0.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(cursor.into_inner()).file_name("scripted.zip"),
        );
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let scripted: serde_json::Value = r.json().await.unwrap();
    let scripted_id = scripted["id"].as_str().unwrap().to_string();

    // 4. "Edit as next version": new config, base bundle carries the script over.
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({
            "name": "scripted",
            "version": "1.0.1",
            "config_json": { "settings": { "new": "2" } },
            "base_bundle_id": scripted_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201, "compose v2: {:?}", r.text().await);
    let v2: serde_json::Value = r.json().await.unwrap();
    let v2_id = v2["id"].as_str().unwrap().to_string();

    let cfg2: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/bundles/{}/config", s.base_url, v2_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        cfg2["config_json"],
        serde_json::json!({ "settings": { "new": "2" } })
    );
    assert_eq!(
        cfg2["scripts"],
        serde_json::json!(["scripts/check_disk.ps1"]),
        "script must be carried into the new version"
    );

    // 5. Same (name, version) again -> conflict; the UI tells the user to bump.
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({
            "name": "scripted",
            "version": "1.0.1",
            "config_json": {},
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    // 6. Config must be an object; bad names rejected.
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({ "name": "x", "version": "1", "config_json": [1, 2] }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({ "name": "bad name!", "version": "1", "config_json": {} }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}
