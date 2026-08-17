use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_storage::Db;
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    _tempdir: TempDir,
    handles: Vec<tokio::task::JoinHandle<()>>,
    _db: Db,
    trust_store: fleet_server::mtls::MtlsContext,
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

    // Bind both ports up-front so we can build the absolute base_url before serving.
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
        agent_limits: fleet_server::agent_limits::AgentRateLimits::new(),
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::default(),
        trust_store: trust_store.clone(),
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    let trust_store_handle = trust_store.clone();

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

    // Wait for HTTP listener to be ready
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
        _db: db,
        trust_store: trust_store_handle,
        cookie_jar: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

async fn signup_and_login(s: &TestServer) {
    use sha2::{Digest, Sha256};

    // Signup creates the tenant + tenant secrets
    s.cookie_jar
        .post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "tenant_slug": "acme",
            "tenant_name": "Acme",
            "turnstile_token": ""
        }))
        .send()
        .await
        .unwrap();

    // Send-link is uniform 204; instead, fabricate a magic link directly via repos.
    let tenants = fleet_storage::TenantRepo::new(&s._db);
    let users = fleet_storage::UserRepo::new(&s._db);
    let links = fleet_storage::MagicLinkRepo::new(&s._db);
    let t = tenants.get_by_slug("acme").await.unwrap().unwrap();
    let u = users
        .find_by_email("alice@example.com")
        .await
        .unwrap()
        .unwrap();
    let token = "test-magic-link-XXXXXXXX";
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let hash: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();

    let r = s
        .cookie_jar
        .get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303);
}

#[tokio::test]
async fn end_to_end_enrollment_and_heartbeat() {
    let s = start().await;
    signup_and_login(&s).await;

    // POST /api/hosts
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "POST /api/hosts: {:?}", r.text().await);
    let create: serde_json::Value = r.json().await.unwrap();
    let bootstrap_token = create["bootstrap_token"].as_str().unwrap().to_string();

    // Belt-and-braces only: `enroll` now awaits `ensure_tenant_trusted`, so the CA is
    // loaded before the response is sent (see
    // `a_new_tenants_ca_is_trusted_before_enrollment_answers`). The loop stays to absorb
    // unrelated transient startup errors.
    let mut last_err = String::from("not attempted");
    let mut enrolled = None;
    for _ in 0..20 {
        // Force a rebuild
        s.cookie_jar
            .get(format!("{}/healthz", s.base_url))
            .send()
            .await
            .ok();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        match fleet_agent_sim::enroll(&s.base_url, &bootstrap_token, Some("alpha"), Some("linux"))
            .await
        {
            Ok(a) => {
                enrolled = Some(a);
                break;
            }
            Err(e) => last_err = format!("{e:?}"),
        }
    }
    let agent = enrolled.unwrap_or_else(|| panic!("agent enroll failed after retries: {last_err}"));

    // Trust store rebuild after enrollment to load this host's CA into the verifier (no-op
    // here — CA was already in the store from signup — but exercised in real flow).
    s.cookie_jar
        .get(format!("{}/healthz", s.base_url))
        .send()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // mTLS heartbeat. Capped at 8 attempts so we stay under the per-host 10/min limiter
    // when retries do happen (trust-store rebuild lag) — exhausting the quota would mask
    // the real handshake failure with a misleading 429.
    let mut last_err = String::from("not attempted");
    let mut ok = false;
    for _ in 0..8 {
        match agent.heartbeat().await {
            Ok(_) => {
                ok = true;
                break;
            }
            Err(e) => last_err = format!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ok, "heartbeat failed: {last_err}");
}

#[tokio::test]
async fn enroll_with_bad_bootstrap_token_rejected() {
    let s = start().await;
    signup_and_login(&s).await;

    let result = fleet_agent_sim::enroll(&s.base_url, "not-a-real-jwt", None, None).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn enroll_replay_rejected() {
    let s = start().await;
    signup_and_login(&s).await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let create: serde_json::Value = r.json().await.unwrap();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    // First enroll succeeds (with retries while trust store catches up)
    let mut first = None;
    for _ in 0..20 {
        if let Ok(a) = fleet_agent_sim::enroll(&s.base_url, &token, None, None).await {
            first = Some(a);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(first.is_some());

    // Second enroll with the same token must fail
    let second = fleet_agent_sim::enroll(&s.base_url, &token, None, None).await;
    assert!(second.is_err(), "replay must fail");
}

#[tokio::test]
async fn deleted_host_is_cut_off_and_gone() {
    let s = start().await;
    signup_and_login(&s).await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let create: serde_json::Value = r.json().await.unwrap();
    let host_id = create["host_id"].as_str().unwrap().to_string();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    // Enroll (retry for trust-store rebuild lag) and prove the agent is live.
    let mut agent = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(a) = fleet_agent_sim::enroll(&s.base_url, &token, Some("doomed"), None).await {
            agent = Some(a);
            break;
        }
    }
    let agent = agent.expect("enroll failed");
    let mut alive = false;
    for _ in 0..8 {
        if agent.heartbeat().await.is_ok() {
            alive = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(alive, "agent must be able to heartbeat before deletion");

    // Give the host a tag and an override so the cascade has something to clean up.
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/env", s.base_url, host_id))
        .json(&serde_json::json!({ "value": "prod" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({ "patch": { "secret": "x" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // Delete.
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{}", s.base_url, host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204, "delete failed");

    // Gone from the list, 404 on detail and on a second delete.
    let hosts: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(hosts.as_array().unwrap().is_empty());
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{}", s.base_url, host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // The live agent is cut off: its cert serial no longer resolves as active.
    let hb = agent.heartbeat().await;
    assert!(hb.is_err(), "deleted host's heartbeat must be rejected");

    // No orphans left behind.
    for table in ["host_tags", "host_overrides", "host_certs"] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE host_id = ?"))
            .bind(&host_id)
            .fetch_one(&s._db.read)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table} rows must be deleted");
    }

    // Audit trail records the deletion.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'host.deleted' AND target_id = ?",
    )
    .bind(&host_id)
    .fetch_one(&s._db.read)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

/// Regression: a freshly created tenant's CA is not in the mTLS trust store until a rebuild
/// runs, and enrollment used to trigger that rebuild with a spawned, unawaited task. The
/// enroll response could therefore reach the agent first, and its opening mTLS connection
/// died with `UnknownCA` — while the server logged "not signed by any known tenant CA —
/// re-enroll the host", which is the wrong advice for a perfectly good enrollment.
///
/// Deterministic on purpose: rather than racing the scheduler, it asserts the gap exists
/// right after signup and that `ensure_tenant_trusted` closes it before returning.
#[tokio::test]
async fn a_new_tenants_ca_is_trusted_before_enrollment_answers() {
    let s = start().await;
    signup_and_login(&s).await;

    let tenant = fleet_storage::TenantRepo::new(&s._db)
        .get_by_slug("acme")
        .await
        .unwrap()
        .expect("signup created the tenant");

    // The gap this guards. Signup writes the CA to the database but nothing has reloaded
    // the in-memory trust store yet, so an mTLS handshake right now would be rejected.
    assert!(
        !s.trust_store.trusts_tenant(tenant.id),
        "precondition: a newly created tenant's CA is not yet loaded"
    );

    s.trust_store
        .ensure_tenant_trusted(tenant.id)
        .await
        .expect("the CA exists in the database, so a rebuild must pick it up");

    assert!(
        s.trust_store.trusts_tenant(tenant.id),
        "after ensure_tenant_trusted the CA must be usable for client-cert verification"
    );

    // Idempotent, and cheap the second time — no rebuild, just the in-memory check.
    s.trust_store
        .ensure_tenant_trusted(tenant.id)
        .await
        .unwrap();
    assert!(s.trust_store.trusts_tenant(tenant.id));
}

/// The end-to-end shape of the same bug: enroll, then immediately use the certificate with
/// no intervening delay. With the awaited guarantee in `enroll` this cannot race.
#[tokio::test]
async fn a_freshly_enrolled_host_can_connect_immediately() {
    let s = start().await;
    signup_and_login(&s).await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let create: serde_json::Value = r.json().await.unwrap();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    let agent = fleet_agent_sim::enroll(&s.base_url, &token, Some("first-host"), Some("linux"))
        .await
        .expect("first enrollment for a brand-new tenant must succeed");

    // No sleep, no retry: the enroll response is only correct if the CA is already loaded.
    agent
        .heartbeat()
        .await
        .expect("the first mTLS call after enrollment must not race the trust store");
}

/// "Add host" writes a row before anyone runs the install command, so the operator views
/// have to distinguish three states — not two. The one that matters is `never_enrolled`:
/// the token has expired, `mark_enrolled_if_pending` will refuse it forever, and the row is
/// only good for deleting.
#[tokio::test]
async fn host_status_separates_never_enrolled_from_awaiting() {
    let s = start().await;
    signup_and_login(&s).await;

    let create_host = |s: &TestServer| {
        let req = s
            .cookie_jar
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}));
        async move {
            let v: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
            (
                v["host_id"].as_str().unwrap().to_string(),
                v["bootstrap_token"].as_str().unwrap().to_string(),
            )
        }
    };

    let status_of = |s: &TestServer, host_id: String| {
        let req = s.cookie_jar.get(format!("{}/api/hosts", s.base_url));
        async move {
            let hosts: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
            hosts
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["id"].as_str() == Some(&host_id))
                .unwrap_or_else(|| panic!("host {host_id} missing from list"))["status"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };

    // Freshly added, install command not run: still actionable.
    let (waiting_id, _) = create_host(&s).await;
    assert_eq!(
        status_of(&s, waiting_id.clone()).await,
        "awaiting_enrollment"
    );

    // A host that ran the command has enrolled, and the status moves on to describing what
    // it is doing: it is in contact but has not reported applying anything yet (retried
    // while the trust store catches up, as elsewhere in this file).
    let (enrolled_id, token) = create_host(&s).await;
    let mut enrolled = false;
    for _ in 0..20 {
        if fleet_agent_sim::enroll(&s.base_url, &token, Some("beta"), Some("linux"))
            .await
            .is_ok()
        {
            enrolled = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(enrolled, "enroll failed after retries");
    assert_eq!(status_of(&s, enrolled_id).await, "out_of_sync");

    // Let the first host's token lapse. Nothing else about the row changes.
    sqlx::query("UPDATE hosts SET bootstrap_expires_at = ? WHERE id = ?")
        .bind(fleet_core::time::now_unix() - 1)
        .bind(&waiting_id)
        .execute(&s._db.write)
        .await
        .unwrap();

    assert_eq!(status_of(&s, waiting_id.clone()).await, "never_enrolled");

    // The detail endpoint must agree — it is the same derivation, and an operator who opens
    // the host from a "never enrolled" row must not see a different story.
    let detail: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts/{}", s.base_url, waiting_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["status"], serde_json::json!("never_enrolled"));
}
