//! Host facts end to end: the hash exchange on polls and state reports, the upload on a
//! miss, and what the operator API shows afterwards.
//!
//! The harness is poll_flow's.

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
        tls: None,
        database_path: PathBuf::from(&db_path),
        base_url: base_url.clone(),
        on_prem: false,
        on_prem_admin_email: None,
        on_prem_admin_password: None,
        on_prem_admin_password_hash: None,
        platform_admin_emails: Vec::new(),
        magic_link_ttl_secs: 900,
        session_ttl_secs: 3600,
        session_idle_ttl_secs: 3600,
        bootstrap_ttl_secs: 3600,
        host_lost_after_secs: 172_800,
        client_cert_lifetime_days: 90,
        cookie_secure: false,
        daily_email_budget: 1_000_000,
        smtp: None,
        turnstile_secret: None,
        turnstile_site_key: None,
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

    let mtls_state = state.clone();
    let mtls_handle = tokio::spawn(async move {
        let r = fleet_server::mtls_router(mtls_state.clone());
        let _ = fleet_server::mtls::serve_on(
            mtls_listener,
            mtls_state.trust_store,
            r,
            fleet_server::shutdown::Shutdown::never(),
        )
        .await;
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
    let _ = complete_exchange(&s.cookie_jar, &s.base_url, &token).await;
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

use fleet_agent_sim::facts_upload_body;
use fleet_core::facts::{sha256_hex, EMPTY_FACTS_HASH};

const OS_DOC: &str = r#"{"os":{"arch":"x86_64","family":"linux","name":"Ubuntu 24.04"},"storage":{"volumes":[{"device":"/dev/vda","id":"/","size_bytes":270553174016,"type":"fixed"}]}}"#;
const OS_DOC_2: &str = r#"{"os":{"arch":"x86_64","family":"linux","name":"Ubuntu 24.04.1"},"storage":{"volumes":[{"device":"/dev/vda","id":"/","size_bytes":270553174016,"type":"fixed"},{"id":"/data","type":"fixed"}]}}"#;

/// Enroll, on a tier whose request budget a whole test fits in.
async fn setup() -> (TestServer, fleet_agent_sim::EnrolledAgent, String) {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    sqlx::query("UPDATE tenants SET tier = 'enterprise'")
        .execute(&s.db.write)
        .await
        .unwrap();
    let agent = enroll_a_host(&s).await;
    let host_id: String = sqlx::query_scalar("SELECT id FROM hosts LIMIT 1")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    (s, agent, host_id)
}

async fn facts_view(s: &TestServer, host_id: &str) -> serde_json::Value {
    let r = s
        .cookie_jar
        .get(format!("{}/api/hosts/{host_id}/facts", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

#[tokio::test]
async fn a_host_with_nothing_enabled_is_answered_and_never_asked_for_more() {
    let (s, agent, host_id) = setup().await;

    let (_, held) = agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    // `none`: the server does facts and holds nothing. The agent reads that as the empty
    // document, which is what it has, so it uploads nothing.
    assert_eq!(held.as_deref(), Some("none"));

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "nothing_enabled");
    assert!(v["facts"].is_null());
    assert_eq!(v["reported_hash"], EMPTY_FACTS_HASH);
    assert_eq!(v["changes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn an_agent_without_facts_is_still_told_the_hash_and_shows_not_reported() {
    let (s, agent, host_id) = setup().await;
    // The older poll shape: no facts_hash at all. The header is still sent — it costs the
    // agent nothing to ignore.
    agent.fetch_desired_state(None).await.unwrap();
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "not_reported");
    assert!(v["reported_hash"].is_null());
}

#[tokio::test]
async fn the_document_is_uploaded_once_on_a_miss_and_then_only_the_hash_travels() {
    let (s, agent, host_id) = setup().await;
    let hash = sha256_hex(OS_DOC.as_bytes());

    let (first, held) = agent.poll_with_facts(None, &hash).await.unwrap();
    assert_eq!(
        held.as_deref(),
        Some("none"),
        "a miss: the server holds nothing"
    );
    assert_eq!(facts_view(&s, &host_id).await["status"], "pending");

    let (status, held) = agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(held.as_deref(), Some(hash.as_str()));

    // The next poll — a 304, the steady state — answers with the hash we now hold, so the
    // agent has nothing more to send.
    s.agent_limits.forget_last_poll(&host_id);
    let state_hash = first.unwrap().state_hash;
    let (again, held) = agent
        .poll_with_facts(Some(&state_hash), &hash)
        .await
        .unwrap();
    assert!(again.is_none(), "in sync: 304");
    assert_eq!(held.as_deref(), Some(hash.as_str()));

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "current");
    assert_eq!(v["facts_hash"], hash);
    assert_eq!(v["collected_at"], "2026-09-25T10:00:00Z");
    assert_eq!(v["size_bytes"], OS_DOC.len());
    assert_eq!(v["facts"]["os"]["family"], "linux");
    assert_eq!(v["facts"]["storage"]["volumes"][0]["id"], "/");
    let changes = v["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["initial"], true);

    // Stored verbatim: the bytes still hash to what they were filed under.
    let stored: String = sqlx::query_scalar("SELECT facts_json FROM host_facts WHERE host_id = ?")
        .bind(&host_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(stored, OS_DOC);
}

#[tokio::test]
async fn a_state_report_is_answered_with_the_held_hash_too() {
    let (s, agent, host_id) = setup().await;
    let hash = sha256_hex(OS_DOC.as_bytes());
    let held = agent
        .report_state_with_facts(None, Default::default(), &hash)
        .await
        .unwrap();
    assert_eq!(held.as_deref(), Some("none"));

    agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    let held = agent
        .report_state_with_facts(None, Default::default(), &hash)
        .await
        .unwrap();
    assert_eq!(held.as_deref(), Some(hash.as_str()));
    assert_eq!(facts_view(&s, &host_id).await["status"], "current");
}

#[tokio::test]
async fn a_newer_document_is_diffed_by_record_id() {
    let (s, agent, host_id) = setup().await;
    for doc in [OS_DOC, OS_DOC_2] {
        let (status, _) = agent
            .upload_facts(facts_upload_body(doc, "2026-09-25T10:00:00Z"))
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["facts_hash"], sha256_hex(OS_DOC_2.as_bytes()));
    let changes = v["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2, "the first document, then one diff");
    let latest = &changes[0];
    assert_eq!(latest["initial"], false);
    let paths: Vec<(&str, &str)> = latest["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["path"].as_str().unwrap(), c["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(
        paths,
        vec![("os.name", "changed"), ("storage.volumes[/data]", "added"),]
    );
    assert_eq!(latest["changes"][0]["old"], "Ubuntu 24.04");
    assert_eq!(latest["changes"][0]["new"], "Ubuntu 24.04.1");
}

#[tokio::test]
async fn a_repeated_upload_changes_nothing() {
    let (s, agent, host_id) = setup().await;
    for _ in 0..2 {
        let (status, _) = agent
            .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["changes"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_agent_with_a_newer_document_reads_as_outdated() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    let newer = sha256_hex(OS_DOC_2.as_bytes());
    let (_, held) = agent.poll_with_facts(None, &newer).await.unwrap();
    assert_eq!(
        held.as_deref(),
        Some(sha256_hex(OS_DOC.as_bytes()).as_str())
    );
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "outdated");
    assert_eq!(v["reported_hash"], newer);
    // Still showing what we have, rather than nothing.
    assert_eq!(v["facts"]["os"]["name"], "Ubuntu 24.04");
}

#[tokio::test]
async fn an_upload_whose_hash_does_not_match_is_refused() {
    let (s, agent, host_id) = setup().await;
    let body = format!(
        "{{\"collected_at\":\"t\",\"facts\":{OS_DOC},\"facts_hash\":\"{}\"}}",
        sha256_hex(b"something else")
    );
    let (status, _) = agent.upload_facts(body).await.unwrap();
    assert_eq!(status, 400);
    let (status, _) = agent.upload_facts("[]".into()).await.unwrap();
    assert_eq!(status, 400);
    let v = facts_view(&s, &host_id).await;
    assert!(v["facts"].is_null());
}

#[tokio::test]
async fn an_oversized_upload_is_refused_as_too_large() {
    let (s, agent, host_id) = setup().await;
    let big = format!(
        "{{\"blob\":{{\"data\":\"{}\"}}}}",
        "x".repeat(fleet_server::facts::MAX_FACTS_BODY_BYTES)
    );
    let (status, _) = agent
        .upload_facts(facts_upload_body(&big, "t"))
        .await
        .unwrap();
    // 413 is what the agent reads as "turn a set off", and does not retry.
    assert_eq!(status, 413);
    assert!(facts_view(&s, &host_id).await["facts"].is_null());
}

#[tokio::test]
async fn facts_of_an_unknown_host_are_not_found() {
    let (s, _agent, _host_id) = setup().await;
    let r = s
        .cookie_jar
        .get(format!("{}/api/hosts/nope/facts", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn deleting_a_host_deletes_its_facts() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{host_id}", s.base_url))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    for table in ["host_facts", "host_fact_changes"] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&s.db.read)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
}

/// Complete a magic-link sign-in the browser way: GET renders the confirmation page and sets
/// the `fleet_exchange` double-submit cookie, then the form POST redeems the token. The
/// client must carry a cookie store so the cookie is resent on the POST.
async fn complete_exchange(c: &reqwest::Client, base_url: &str, token: &str) -> reqwest::Response {
    let page = c
        .get(format!("{base_url}/api/auth/exchange?t={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200, "confirmation page must render on GET");
    let html = page.text().await.unwrap();
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("csrf field present") + marker.len();
    let end = html[start..].find('"').expect("csrf value terminated");
    let csrf = html[start..start + end].to_string();
    c.post(format!("{base_url}/api/auth/exchange"))
        .form(&[("t", token), ("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap()
}
