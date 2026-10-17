//! The test servers and steps shared by the integration tests. New tests should use these
//! rather than copy them.
//!
//! - [`start`] / [`start_with`]: the real routers on ephemeral ports (operator HTTP and agent
//!   mTLS) over a fresh database. [`start_with`] adjusts the state (a limit, a config value)
//!   before the server comes up.
//! - [`start_http`]: only the operator router, with one tenant (`acme`) already created, for
//!   tests about what a signed-in user may do; [`signed_in`] mints them a session directly.
//! - [`test_config`]: the configuration every harness starts from. A `Config` field added
//!   later is added here once.
//! - [`sign_up_and_in`], [`complete_exchange`], [`enroll_a_host`]: the steps most tests open
//!   with.
//!
//! auth_flow, mux_flow and shutdown_flow still build their own servers — on-prem config,
//! the shared-port listener, their own lifecycle — but start from [`test_config`] where they
//! build a `Config`, and use the shared steps.
//!
//! Each test binary compiles its own copy of this module and uses a different subset of it.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::crypto::aead::MasterKey;
use fleet_core::user::Role;
use fleet_server::auth::tokens::hash_token;
use fleet_storage::{Db, SessionRepo, TenantRepo, UserRepo};
use tempfile::TempDir;

pub struct TestServer {
    pub base_url: String,
    pub _tempdir: TempDir,
    pub handles: Vec<tokio::task::JoinHandle<()>>,
    pub db: Db,
    pub agent_limits: fleet_server::agent::limits::AgentRateLimits,
    /// The state the routers were built with: its caches, trust store and config are the
    /// live ones.
    pub state: fleet_server::AppState,
    pub cookie_jar: reqwest::Client,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

pub async fn start() -> TestServer {
    start_with(|_| {}).await
}

/// [`start`], with `tweak` applied to the state before the routers are built.
pub async fn start_with(tweak: impl FnOnce(&mut fleet_server::AppState)) -> TestServer {
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

    let cfg = fleet_server::runtime::config::Config {
        listen: format!("127.0.0.1:{}", http_addr.port()),
        listen_mtls: format!("127.0.0.1:{}", mtls_addr.port()),
        agent_mtls_url: format!("https://127.0.0.1:{}", mtls_addr.port()),
        base_url: base_url.clone(),
        master_key,
        bootstrap_jwt_secret,
        ..test_config(PathBuf::from(&db_path))
    };

    let (mtls_cert_pem, mtls_key_pem) =
        fleet_server::transport::mtls::generate_self_signed_server("127.0.0.1").unwrap();

    let email = fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap();
    let turnstile =
        fleet_server::auth::turnstile::Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget);
    let agent_limits = fleet_server::agent::limits::AgentRateLimits::new();
    let trust_store = fleet_server::transport::mtls::MtlsContext::load(
        db.clone(),
        mtls_cert_pem.clone(),
        mtls_key_pem,
    )
    .await
    .unwrap();

    let agent_limits_handle = agent_limits.clone();
    let mut state = fleet_server::AppState {
        db: db.clone(),
        config: cfg.clone(),
        email,
        turnstile,
        rate_limits,
        agent_limits,
        enrollment_limits: fleet_server::agent::limits::EnrollmentLimits::default(),
        trust_store: trust_store.clone(),
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
        facts_catalog_cache: Default::default(),
    };
    tweak(&mut state);
    let state_handle = state.clone();

    let mtls_state = state.clone();
    let mtls_handle = tokio::spawn(async move {
        let r = fleet_server::mtls_router(mtls_state.clone());
        let _ = fleet_server::transport::mtls::serve_on(
            mtls_listener,
            mtls_state.trust_store,
            r,
            fleet_server::runtime::shutdown::Shutdown::never(),
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
        state: state_handle,
        cookie_jar: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

/// The configuration every harness starts from: cloud mode, no SMTP or Turnstile, a generous
/// email budget, and a fresh master key. Callers override the listeners and URLs they use.
pub fn test_config(db_path: PathBuf) -> fleet_server::runtime::config::Config {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let key_b64 = MasterKey::generate_b64();
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();
    fleet_server::runtime::config::Config {
        listen: "127.0.0.1:0".into(),
        listen_https: "127.0.0.1:0".into(),
        listen_mtls: "127.0.0.1:0".into(),
        agent_mtls_url: "https://127.0.0.1".into(),
        acme: None,
        tls: None,
        database_path: db_path,
        base_url: "http://localhost".into(),
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
    }
}

/// Only the operator HTTP router, over a fresh database with one tenant (`acme`) already
/// created. For tests about what a signed-in user may do, where how they signed in is not
/// the point — `auth_flow` covers that.
pub struct HttpServer {
    pub base_url: String,
    pub _tempdir: TempDir,
    pub handle: tokio::task::JoinHandle<()>,
    pub db: Db,
    pub tenant_id: i64,
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub async fn start_http() -> HttpServer {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let cfg = test_config(db_path);
    let (mtls_cert_pem, mtls_key_pem) =
        fleet_server::transport::mtls::generate_self_signed_server("127.0.0.1").unwrap();
    let email = fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap();
    let turnstile =
        fleet_server::auth::turnstile::Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget);
    let trust_store = fleet_server::transport::mtls::MtlsContext::load(
        db.clone(),
        mtls_cert_pem.clone(),
        mtls_key_pem,
    )
    .await
    .unwrap();

    let state = fleet_server::AppState {
        db: db.clone(),
        config: cfg,
        email,
        turnstile,
        rate_limits,
        agent_limits: fleet_server::agent::limits::AgentRateLimits::new(),
        enrollment_limits: fleet_server::agent::limits::EnrollmentLimits::default(),
        trust_store,
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
        facts_catalog_cache: Default::default(),
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

    for _ in 0..50 {
        if reqwest::get(format!("{base_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let tenant = TenantRepo::new(&db)
        .create("acme", "Acme", "free", None)
        .await
        .unwrap();

    HttpServer {
        base_url,
        _tempdir: dir,
        handle,
        db,
        tenant_id: tenant.id,
    }
}

/// A client that sends `token` as its session cookie, and does not follow redirects.
pub fn client_with_session(base_url: &str, token: &str) -> reqwest::Client {
    let jar = reqwest::cookie::Jar::default();
    jar.add_cookie_str(
        &format!("fleet_session={token}; Path=/"),
        &base_url.parse().unwrap(),
    );
    reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// A user of `role` in the given tenant, plus a client already holding their session cookie.
/// The session is minted directly rather than through the magic-link flow.
pub async fn signed_in_for(
    s: &HttpServer,
    tenant_id: i64,
    email: &str,
    role: Role,
) -> (i64, reqwest::Client) {
    let user = UserRepo::new(&s.db)
        .create(tenant_id, email, role)
        .await
        .unwrap();
    let token = format!("session-for-{email}");
    SessionRepo::new(&s.db)
        .create(&hash_token(&token), tenant_id, user.id, 3600)
        .await
        .unwrap();
    (user.id, client_with_session(&s.base_url, &token))
}

/// [`signed_in_for`] in the server's own tenant.
pub async fn signed_in(s: &HttpServer, email: &str, role: Role) -> (i64, reqwest::Client) {
    signed_in_for(s, s.tenant_id, email, role).await
}

/// Sign `email` up as the owner of a new tenant `slug`, then sign them in on `c`: the
/// sign-up request, a magic link planted in the database (send-link always answers 204, so
/// the real one cannot be read back), and the browser-style exchange, which must answer 303.
pub async fn sign_up_and_in(
    c: &reqwest::Client,
    base_url: &str,
    db: &Db,
    slug: &str,
    tenant_name: &str,
    email: &str,
) {
    c.post(format!("{base_url}/api/auth/signup"))
        .json(&serde_json::json!({
            "email": email,
            "tenant_slug": slug,
            "tenant_name": tenant_name,
            "turnstile_token": "",
        }))
        .send()
        .await
        .unwrap();

    let t = TenantRepo::new(db)
        .get_by_slug(slug)
        .await
        .unwrap()
        .unwrap();
    let u = UserRepo::new(db)
        .find_by_email(email)
        .await
        .unwrap()
        .unwrap();
    let token = format!("magic-{slug}-XXXXXXXX");
    fleet_storage::MagicLinkRepo::new(db)
        .create(
            &hash_token(&token),
            t.id,
            u.id,
            fleet_core::time::now_unix() + 600,
        )
        .await
        .unwrap();
    let r = complete_exchange(c, base_url, &token).await;
    assert_eq!(r.status(), 303, "magic-link exchange must sign {email} in");
}

/// [`sign_up_and_in`] on the server's own cookie jar, the tenant named after its slug.
pub async fn signup_login(s: &TestServer, slug: &str, email: &str) {
    sign_up_and_in(
        &s.cookie_jar,
        &s.base_url,
        &s.db,
        slug,
        &slug.to_uppercase(),
        email,
    )
    .await;
}

pub async fn enroll_a_host(s: &TestServer) -> fleet_agent_sim::EnrolledAgent {
    enroll_a_host_with_id(s).await.0
}

/// [`enroll_a_host`], also returning the host id the server assigned.
pub async fn enroll_a_host_with_id(s: &TestServer) -> (fleet_agent_sim::EnrolledAgent, String) {
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

    // Trust store rebuild can lag; retry briefly
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

/// Complete a magic-link sign-in the browser way: GET renders the confirmation page and sets
/// the `fleet_exchange` double-submit cookie, then the form POST redeems the token. The
/// client must carry a cookie store so the cookie is resent on the POST.
pub async fn complete_exchange(
    c: &reqwest::Client,
    base_url: &str,
    token: &str,
) -> reqwest::Response {
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
