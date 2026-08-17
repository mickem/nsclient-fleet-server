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
    desired_state_cache: Arc<fleet_server::desired_state::DesiredStateCache>,
    state: fleet_server::AppState,
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
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    let cache_handle = state.desired_state_cache.clone();
    let state_handle = state.clone();

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
        desired_state_cache: cache_handle,
        state: state_handle,
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

async fn enroll_a_host(s: &TestServer) -> fleet_agent_sim::EnrolledAgent {
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let token = body["bootstrap_token"].as_str().unwrap().to_string();

    // Trust store rebuild can lag; retry briefly
    let mut last = String::new();
    for _ in 0..20 {
        match fleet_agent_sim::enroll(&s.base_url, &token, Some("alpha"), Some("linux")).await {
            Ok(a) => return a,
            Err(e) => last = format!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("enroll never succeeded: {last}");
}

#[tokio::test]
async fn desired_state_roundtrip_with_304() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let agent = enroll_a_host(&s).await;

    let first = agent.fetch_desired_state(None).await.unwrap();
    let st = first.expect("first call must return 200");
    assert!(!st.state_hash.is_empty());
    assert!(st.next_poll_in_seconds > 0);

    // Skip the poll-interval floor for this test (otherwise we'd wait min_poll_interval).
    let host_id = host_id_from_db(&s.db).await;
    s.agent_limits.forget_last_poll(&host_id);
    let second = agent
        .fetch_desired_state(Some(&st.state_hash))
        .await
        .unwrap();
    assert!(second.is_none(), "matching hash must produce 304");
}

async fn host_id_from_db(db: &Db) -> String {
    sqlx::query_scalar("SELECT id FROM hosts LIMIT 1")
        .fetch_one(&db.read)
        .await
        .unwrap()
}

#[tokio::test]
async fn state_report_records_tags_and_bumps_config_version() {
    let s = start().await;
    signup_login(&s, "beta", "bob@example.com").await;
    let agent = enroll_a_host(&s).await;

    let v_before: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();

    let mut tags = BTreeMap::new();
    tags.insert("os".into(), "linux".into());
    tags.insert("sql_server_present".into(), "true".into());
    agent
        .report_state(Some("phase4-test-hash"), tags)
        .await
        .unwrap();

    let v_after: i64 = sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert!(v_after > v_before, "config_version must bump on tag change");

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM host_tags WHERE source = 'agent'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(row_count, 2);

    // Re-reporting the same tags must NOT bump config_version (idempotent agent reports)
    let mut same = BTreeMap::new();
    same.insert("os".into(), "linux".into());
    same.insert("sql_server_present".into(), "true".into());
    agent.report_state(None, same).await.unwrap();
    let v_after2: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(v_after2, v_after, "no-op report must not bump version");

    let stored_hash: Option<String> =
        sqlx::query_scalar("SELECT current_state_hash FROM hosts LIMIT 1")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(stored_hash.as_deref(), Some("phase4-test-hash"));
}

/// The agent reports *whether* the host carries configuration of its own that outranks what
/// we send it — never what that configuration is.
///
/// The state that needs proving is the third one. "Never reported" is not "reported no": an
/// agent older than the field says nothing, and reading that as a denial would tell an
/// operator a host is fully fleet-managed on no evidence at all. So the column stays NULL
/// until an agent answers, and a later silent report must not undo an answer already given.
#[tokio::test]
async fn a_host_reports_whether_local_configuration_outranks_the_fleet() {
    let s = start().await;
    signup_login(&s, "gamma", "gwen@example.com").await;
    let agent = enroll_a_host(&s).await;

    let stored = || async {
        sqlx::query_scalar::<_, Option<i64>>("SELECT local_config_present FROM hosts LIMIT 1")
            .fetch_one(&s.db.read)
            .await
            .unwrap()
    };
    // What the operator API says, which is what the UI renders.
    let published = || async {
        let hosts: serde_json::Value = s
            .cookie_jar
            .get(format!("{}/api/hosts", s.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        hosts[0]["local_config_present"].clone()
    };

    assert_eq!(stored().await, None, "unknown until an agent answers");
    assert_eq!(published().await, serde_json::Value::Null);

    // An agent that predates the field: silence changes nothing.
    agent
        .report_state(Some("h1"), BTreeMap::new())
        .await
        .unwrap();
    assert_eq!(stored().await, None, "an omitted field is not an answer");

    // Reported clean.
    agent
        .report_state_with_local_config(Some("h1"), BTreeMap::new(), false)
        .await
        .unwrap();
    assert_eq!(stored().await, Some(0));
    assert_eq!(published().await, serde_json::json!(false));

    // Someone edits nsclient.ini on the box.
    agent
        .report_state_with_local_config(Some("h1"), BTreeMap::new(), true)
        .await
        .unwrap();
    assert_eq!(stored().await, Some(1));
    assert_eq!(published().await, serde_json::json!(true));

    // A report that omits the field must not silently clear what we were told.
    agent
        .report_state(Some("h1"), BTreeMap::new())
        .await
        .unwrap();
    assert_eq!(
        stored().await,
        Some(1),
        "silence must not retract a reported answer"
    );

    // And it comes back down when the local configuration is removed.
    agent
        .report_state_with_local_config(Some("h1"), BTreeMap::new(), false)
        .await
        .unwrap();
    assert_eq!(stored().await, Some(0));

    // The flag describes the host; it must not touch the tenant's config version, which
    // exists to invalidate desired state. Nothing about it changes what we send.
    let bumps: i64 = sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'gamma'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(bumps, 0, "local config is not an input to desired state");
}

#[tokio::test]
async fn renew_issues_new_cert_and_old_session_keeps_working() {
    let s = start().await;
    signup_login(&s, "gamma", "carol@example.com").await;
    let mut agent = enroll_a_host(&s).await;
    let original_cert = agent.cert_pem.clone();

    agent.renew().await.unwrap();
    assert_ne!(
        agent.cert_pem, original_cert,
        "cert must change after renew"
    );

    // Heartbeat with the new identity must succeed
    let _ = agent.heartbeat().await.unwrap();

    // Server should now have two cert rows for this host (old + new), both active
    let cert_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM host_certs WHERE revoked_at IS NULL")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(cert_count, 2);
}

#[tokio::test]
async fn poll_interval_floor_returns_429() {
    let s = start().await;
    signup_login(&s, "delta", "dave@example.com").await;
    let agent = enroll_a_host(&s).await;

    // First call records last_poll_at
    let _ = agent.fetch_desired_state(None).await.unwrap();
    // Second call immediately after — under min_poll_interval (free tier = 60s)
    let r = agent.fetch_desired_state(None).await;
    assert!(
        r.is_err(),
        "second call within min_poll_interval must hit the floor (got {r:?})"
    );
}

#[tokio::test]
async fn a_repeat_poll_is_served_from_the_desired_state_cache() {
    let s = start().await;
    signup_login(&s, "cache", "carol@example.com").await;
    let agent = enroll_a_host(&s).await;
    let host_id = host_id_from_db(&s.db).await;

    let (h0, m0) = s.desired_state_cache.stats();
    let first = agent.fetch_desired_state(None).await.unwrap();
    let first = first.expect("first poll returns 200");
    let (h1, m1) = s.desired_state_cache.stats();
    assert_eq!(m1 - m0, 1, "the first poll must miss and compute");
    assert_eq!(h1 - h0, 0);

    s.agent_limits.forget_last_poll(&host_id);
    let second = agent.fetch_desired_state(None).await.unwrap();
    let second = second.expect("no current_hash sent, so still a 200");
    let (h2, m2) = s.desired_state_cache.stats();
    assert_eq!(h2 - h1, 1, "the second poll must be served from cache");
    assert_eq!(m2 - m1, 0, "and must not recompute");

    assert_eq!(
        first.state_hash, second.state_hash,
        "a cached answer must be identical to the computed one"
    );
}

#[tokio::test]
async fn a_config_change_is_never_served_from_a_stale_cache() {
    let s = start().await;
    signup_login(&s, "invalidate", "ivan@example.com").await;
    let agent = enroll_a_host(&s).await;
    let host_id = host_id_from_db(&s.db).await;

    let before = agent
        .fetch_desired_state(None)
        .await
        .unwrap()
        .expect("first poll returns 200");

    // A host override both bumps config_version and changes the merged config, so the new
    // state is observable in the hash rather than only in the cache counters.
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({
            "patch": { "log": { "level": "debug" } },
            "priority": 1000
        }))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "override PUT failed: {:?}",
        r.text().await
    );

    let (_, m_before) = s.desired_state_cache.stats();
    s.agent_limits.forget_last_poll(&host_id);
    let after = agent
        .fetch_desired_state(None)
        .await
        .unwrap()
        .expect("poll after the change returns 200");
    let (_, m_after) = s.desired_state_cache.stats();

    assert_eq!(
        m_after - m_before,
        1,
        "the bumped config_version must force a recompute"
    );
    assert_ne!(
        before.state_hash, after.state_hash,
        "the agent must see the new configuration, not the cached one"
    );
    assert_eq!(
        after.merged_config_json,
        serde_json::json!({ "log": { "level": "debug" } }),
        "override should be layered into the merged config"
    );
}

/// Phase 9 gated the desired-state cache on "if profiling shows the lazy recompute is hot".
/// This is that profile. Ignored by default — it is a measurement, not an assertion, and
/// timings make poor CI gates.
///
///     cargo test --test poll_flow -- --ignored --nocapture cache_speedup
#[tokio::test]
#[ignore = "benchmark: run manually with --nocapture"]
async fn cache_speedup_profile() {
    use std::time::Instant;

    let s = start().await;
    signup_login(&s, "bench", "ben@example.com").await;
    let agent = enroll_a_host(&s).await;
    let _ = agent;
    let host_id = host_id_from_db(&s.db).await;

    // A fleet-shaped tenant: enough groups that selector evaluation is not free, and tags
    // for them to match against.
    for (k, v) in [
        ("role", "sql_server"),
        ("env", "prod"),
        ("os", "windows"),
        ("site", "eu-west"),
    ] {
        s.cookie_jar
            .put(format!("{}/api/hosts/{}/tags/{}", s.base_url, host_id, k))
            .json(&serde_json::json!({ "value": v }))
            .send()
            .await
            .unwrap();
    }
    const GROUPS: usize = 50;
    for i in 0..GROUPS {
        s.cookie_jar
            .post(format!("{}/api/groups", s.base_url))
            .json(&serde_json::json!({
                "name": format!("group-{i:03}"),
                "selector": { "clauses": [{"op": "eq", "key": "role", "value": "sql_server"}] }
            }))
            .send()
            .await
            .unwrap();
    }
    s.cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({ "patch": { "log": { "level": "debug" } } }))
        .send()
        .await
        .unwrap();

    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = 'bench'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    let config_version: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'bench'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();

    const N: usize = 2_000;

    let t0 = Instant::now();
    for _ in 0..N {
        fleet_server::desired_state::compute_uncached(&s.state, tenant_id, &host_id)
            .await
            .unwrap();
    }
    let uncached = t0.elapsed();

    // Warm, then measure steady-state hits.
    fleet_server::desired_state::compute_desired_state_at(
        &s.state,
        tenant_id,
        &host_id,
        config_version,
    )
    .await
    .unwrap();
    let t1 = Instant::now();
    for _ in 0..N {
        fleet_server::desired_state::compute_desired_state_at(
            &s.state,
            tenant_id,
            &host_id,
            config_version,
        )
        .await
        .unwrap();
    }
    let cached = t1.elapsed();

    println!(
        "\ndesired-state, {GROUPS} groups, {N} iterations:\n  \
         uncached {:>9.1?}  ({:>7.1?}/call)\n  \
         cached   {:>9.1?}  ({:>7.1?}/call)\n  \
         speedup  {:.1}x\n",
        uncached,
        uncached / N as u32,
        cached,
        cached / N as u32,
        uncached.as_secs_f64() / cached.as_secs_f64(),
    );
}
