//! Phase 9 — fleet convergence harness. Spin 50 agents against a real server, exercise the
//! full Phase 4 + Phase 5 pipeline, assert state lands in the DB.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_storage::Db;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const FLEET_SIZE: usize = 50;

struct TestServer {
    base_url: String,
    _tempdir: TempDir,
    handles: Vec<tokio::task::JoinHandle<()>>,
    db: Db,
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
        // Permissive enrollment quota — fleet bring-up issues 50 tokens in ~1 second
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::new(10_000),
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
        cookie_jar: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

async fn signup_login(s: &TestServer) {
    s.cookie_jar
        .post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": "ops@fleet.example.com",
            "tenant_slug": "fleet",
            "tenant_name": "Fleet",
            "turnstile_token": "",
        }))
        .send()
        .await
        .unwrap();

    let tenants = fleet_storage::TenantRepo::new(&s.db);
    let users = fleet_storage::UserRepo::new(&s.db);
    let links = fleet_storage::MagicLinkRepo::new(&s.db);
    let t = tenants.get_by_slug("fleet").await.unwrap().unwrap();
    let u = users
        .find_by_email("ops@fleet.example.com")
        .await
        .unwrap()
        .unwrap();
    let token = "magic-fleet-XXXXXXXX";
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

    // Bump tenant to enterprise — free tier caps at 5 hosts.
    sqlx::query("UPDATE tenants SET tier = 'enterprise' WHERE slug = 'fleet'")
        .execute(&s.db.write)
        .await
        .unwrap();
}

#[tokio::test]
async fn fifty_agents_enroll_heartbeat_and_report_state() {
    let s = start().await;
    signup_login(&s).await;

    // Step 1: issue 50 bootstrap tokens (one /api/hosts call each).
    let mut tokens: Vec<String> = Vec::with_capacity(FLEET_SIZE);
    for _ in 0..FLEET_SIZE {
        let r = s
            .cookie_jar
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "POST /api/hosts: {:?}", r.text().await);
        let body: serde_json::Value = r.json().await.unwrap();
        tokens.push(body["bootstrap_token"].as_str().unwrap().to_string());
    }
    assert_eq!(tokens.len(), FLEET_SIZE);

    // Step 2: enroll all 50 agents concurrently. The tenant CA was loaded into the trust
    // store at signup, so first-attempt enrollment should succeed.
    let base = s.base_url.clone();
    let enroll_futs = tokens.into_iter().enumerate().map(|(i, tok)| {
        let base = base.clone();
        async move {
            let mut last = String::new();
            for _ in 0..6 {
                match fleet_agent_sim::enroll(
                    &base,
                    &tok,
                    Some(&format!("agent-{i:02}")),
                    Some("linux"),
                )
                .await
                {
                    Ok(a) => return Ok::<_, String>(a),
                    Err(e) => last = format!("{e:?}"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(last)
        }
    });
    let agents: Vec<fleet_agent_sim::EnrolledAgent> = futures::future::join_all(enroll_futs)
        .await
        .into_iter()
        .map(|r| r.expect("enroll failed"))
        .collect();
    assert_eq!(agents.len(), FLEET_SIZE);

    // Step 3: each agent does heartbeat + report a tag, all in parallel. Then we verify
    // state landed in the DB.
    let work = agents.into_iter().enumerate().map(|(i, agent)| async move {
        agent.heartbeat().await.expect("heartbeat");
        let mut tags = BTreeMap::new();
        tags.insert("env".into(), "prod".into());
        tags.insert("agent_index".into(), i.to_string());
        agent
            .report_state(Some(&format!("hash-{i:02}")), tags)
            .await
            .expect("state report");
    });
    futures::future::join_all(work).await;

    // Step 4: assertions on the DB.
    let host_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(host_count, FLEET_SIZE as i64, "all hosts must be enrolled");

    let enrolled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE enrolled_at IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(enrolled, FLEET_SIZE as i64);

    let last_seen_set: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE last_seen_at IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        last_seen_set, FLEET_SIZE as i64,
        "every host should have heartbeat"
    );

    let state_hash_set: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE current_state_hash IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        state_hash_set, FLEET_SIZE as i64,
        "every host reports applied state"
    );

    let agent_tag_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM host_tags WHERE source = 'agent' AND key = 'agent_index'
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        agent_tag_count, FLEET_SIZE as i64,
        "every agent's reported tag must be stored"
    );

    // Step 5: audit log captured the enrollments.
    let enroll_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'host.enrolled'
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(enroll_audit_count, FLEET_SIZE as i64);
}

/// Full convergence: a bundle assigned via a selector over agent-reported tags reaches all
/// 50 agents through the real pipeline — report tags → poll desired state → download +
/// verify bundle → report applied hash — and the server ends up seeing every host in sync.
#[tokio::test]
async fn fifty_agents_converge_on_assigned_bundle() {
    let s = start().await;
    signup_login(&s).await;

    // Operator: upload a bundle, create a group selecting env=prod, assign the bundle.
    let bundle_bytes: Vec<u8> = b"PK\x03\x04-fake-zip-for-convergence-test".to_vec();
    let form = reqwest::multipart::Form::new()
        .text("name", "conv-bundle")
        .text("version", "1.0.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(bundle_bytes).file_name("conv.zip"),
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

    let gres = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "prod",
            "selector": { "clauses": [ { "op": "eq", "key": "env", "value": "prod" } ] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(gres.status(), 201, "group: {:?}", gres.text().await);
    let group: serde_json::Value = gres.json().await.unwrap();

    let ares = s
        .cookie_jar
        .post(format!(
            "{}/api/groups/{}/bundles",
            s.base_url,
            group["id"].as_str().unwrap()
        ))
        .json(&serde_json::json!({ "bundle_id": bundle["id"], "priority": 100 }))
        .send()
        .await
        .unwrap();
    assert_eq!(ares.status(), 204, "assign failed");

    // Issue tokens + enroll the fleet.
    let mut tokens: Vec<String> = Vec::with_capacity(FLEET_SIZE);
    for _ in 0..FLEET_SIZE {
        let r = s
            .cookie_jar
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        tokens.push(body["bootstrap_token"].as_str().unwrap().to_string());
    }

    let base = s.base_url.clone();
    let enroll_futs = tokens.into_iter().enumerate().map(|(i, tok)| {
        let base = base.clone();
        async move {
            let mut last = String::new();
            for _ in 0..6 {
                match fleet_agent_sim::enroll(
                    &base,
                    &tok,
                    Some(&format!("conv-{i:02}")),
                    Some("linux"),
                )
                .await
                {
                    Ok(a) => return Ok::<_, String>(a),
                    Err(e) => last = format!("{e:?}"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(last)
        }
    });
    let agents: Vec<fleet_agent_sim::EnrolledAgent> = futures::future::join_all(enroll_futs)
        .await
        .into_iter()
        .map(|r| r.expect("enroll failed"))
        .collect();

    // Each agent: report the tag that puts it in the group, then poll → download → verify →
    // report applied hash. One poll per agent (the tier's poll-interval floor forbids a
    // rapid second poll; server-side in_sync is asserted via the human API instead).
    let work = agents.iter().map(|agent| async move {
        let mut tags = BTreeMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        agent
            .report_state(None, tags.clone())
            .await
            .expect("tag report");

        let ds = agent
            .fetch_desired_state(None)
            .await
            .expect("poll")
            .expect("expected 200 with new state, got 304");
        assert_eq!(ds.bundles.len(), 1, "bundle must be in desired state");
        let b = &ds.bundles[0];
        let bytes = agent
            .fetch_bundle(
                b["id"].as_str().unwrap(),
                b["sha256"].as_str().unwrap(),
                b["signature"].as_str().unwrap(),
            )
            .await
            .expect("bundle download + sha256 + signature verify");
        assert!(!bytes.is_empty());

        agent
            .report_state(Some(&ds.state_hash), tags)
            .await
            .expect("applied report");
        ds.state_hash
    });
    let hashes: Vec<String> = futures::future::join_all(work).await;

    // Convergence: every agent computed the same desired hash…
    let expected = hashes[0].clone();
    assert!(
        hashes.iter().all(|h| h == &expected),
        "all agents must agree on the state hash"
    );

    // …and the server sees every host in sync with it.
    let synced: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE current_state_hash = ?
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .bind(&expected)
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(synced, FLEET_SIZE as i64, "every host must converge");

    // The operator-facing views agree: list shows the fleet, detail shows in_sync.
    let hosts: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hosts = hosts.as_array().unwrap();
    assert_eq!(hosts.len(), FLEET_SIZE);

    let sample_id = hosts[0]["id"].as_str().unwrap();
    let desired: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts/{}/desired", s.base_url, sample_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(desired["in_sync"], serde_json::json!(true));
    assert_eq!(desired["state_hash"].as_str().unwrap(), expected);
    assert_eq!(desired["bundles"].as_array().unwrap().len(), 1);
}
