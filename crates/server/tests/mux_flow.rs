//! Shared-port mux — the operator UI and agent mTLS on one TCP port.
//!
//! The control API runs on a plain HTTP listener here (agent-sim's enroll call uses a
//! stock reqwest client that would not trust a self-signed test certificate); the mux is
//! bound separately and is what both the browser-shaped client and the agent actually dial.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_storage::Db;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    mux_port: u16,
    web_cert_pem: String,
    mtls_server_cert_pem: String,
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

fn parse_certs(pem: &str) -> Vec<CertificateDer<'static>> {
    let mut out = Vec::new();
    let mut rest = pem.as_bytes();
    while let Some((item, remaining)) = rustls_pemfile::read_one_from_slice(rest).unwrap() {
        rest = remaining;
        if let rustls_pemfile::Item::X509Certificate(c) = item {
            out.push(c);
        }
    }
    out
}

fn parse_key(pem: &str) -> PrivatePkcs8KeyDer<'static> {
    let mut rest = pem.as_bytes();
    while let Some((item, remaining)) = rustls_pemfile::read_one_from_slice(rest).unwrap() {
        rest = remaining;
        if let rustls_pemfile::Item::Pkcs8Key(k) = item {
            return k.clone_key();
        }
    }
    panic!("no pkcs8 key in pem");
}

/// Stand-in for the config `rustls-acme` hands the web branch in production: a real
/// certificate, and no client-certificate request.
fn web_server_config(cert_pem: &str, key_pem: &str) -> Arc<rustls::ServerConfig> {
    let cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(parse_certs(cert_pem), parse_key(key_pem).into())
        .unwrap();
    Arc::new(cfg)
}

async fn start() -> TestServer {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let mux_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mux_port = mux_listener.local_addr().unwrap().port();
    let base_url = format!("http://{http_addr}");

    let key_b64 = MasterKey::generate_b64();
    std::env::set_var("MASTER_KEY", &key_b64);
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();

    let cfg = fleet_server::config::Config {
        listen: format!("127.0.0.1:{}", http_addr.port()),
        listen_https: format!("127.0.0.1:{mux_port}"),
        // Empty — exactly the production shape when ACME is on: no dedicated agent port,
        // agents reach /agent/v1/* through the mux.
        listen_mtls: String::new(),
        agent_mtls_url: format!("https://127.0.0.1:{mux_port}"),
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
    let (web_cert_pem, web_key_pem) =
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
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::new(10_000),
        trust_store: trust_store.clone(),
        mtls_server_cert_pem: Arc::new(mtls_cert_pem.clone()),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    let mux_tls = Arc::new(fleet_server::mux::MuxTls {
        acme_challenge: web_server_config(&web_cert_pem, &web_key_pem),
        web: web_server_config(&web_cert_pem, &web_key_pem),
        agent_sni: None,
    });
    let mux_state = state.clone();
    let mux_handle = tokio::spawn(async move {
        let web = fleet_server::router(mux_state.clone());
        let agent = fleet_server::mtls_router(mux_state.clone());
        let _ = fleet_server::mux::serve_on(
            mux_listener,
            mux_tls,
            mux_state.trust_store.clone(),
            web,
            agent,
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
        mux_port,
        web_cert_pem,
        mtls_server_cert_pem: mtls_cert_pem,
        _tempdir: dir,
        handles: vec![http_handle, mux_handle],
        db,
        cookie_jar: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

async fn signup_and_login(s: &TestServer) {
    use sha2::{Digest, Sha256};

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

    let tenants = fleet_storage::TenantRepo::new(&s.db);
    let users = fleet_storage::UserRepo::new(&s.db);
    let links = fleet_storage::MagicLinkRepo::new(&s.db);
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

    let r = complete_exchange(&s.cookie_jar, &s.base_url, token).await;
    assert_eq!(r.status(), 303);
}

/// A browser: standard ALPN, no client certificate, trusts the web certificate only.
fn browser_client(s: &TestServer) -> reqwest::Client {
    reqwest::Client::builder()
        .add_root_certificate(reqwest::Certificate::from_pem(s.web_cert_pem.as_bytes()).unwrap())
        .build()
        .unwrap()
}

#[tokio::test]
async fn one_port_serves_both_the_ui_and_the_fleet() {
    let s = start().await;
    signup_and_login(&s).await;

    // --- the browser branch -------------------------------------------------------
    let r = browser_client(&s)
        .get(format!("https://127.0.0.1:{}/healthz", s.mux_port))
        .send()
        .await
        .expect("browser-shaped client should reach the web branch");
    assert_eq!(r.status(), 200);
    assert_eq!(r.text().await.unwrap(), "OK");

    // --- the agent branch, same port ----------------------------------------------
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let create: serde_json::Value = r.json().await.unwrap();
    let bootstrap_token = create["bootstrap_token"].as_str().unwrap().to_string();

    // Signup fires an async trust-store rebuild; retry until the tenant CA lands.
    let mut enrolled = None;
    let mut last_err = String::from("not attempted");
    for _ in 0..20 {
        s.cookie_jar
            .get(format!("{}/healthz", s.base_url))
            .send()
            .await
            .ok();
        match fleet_agent_sim::enroll(
            &s.base_url,
            &bootstrap_token,
            Some("mux-host"),
            Some("linux"),
        )
        .await
        {
            Ok(a) => {
                enrolled = Some(a);
                break;
            }
            Err(e) => {
                last_err = e.to_string();
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }
    }
    let agent = enrolled.unwrap_or_else(|| panic!("enroll failed: {last_err}"));

    // The enroll response must point the agent at the shared port, not a dedicated one.
    assert_eq!(
        agent.mtls_url,
        format!("https://127.0.0.1:{}", s.mux_port),
        "agents should be told to dial the muxed port"
    );

    let hb = agent
        .heartbeat()
        .await
        .expect("agent should reach /agent/v1 over the shared port via ALPN");
    assert!(hb.is_object(), "heartbeat body: {hb}");

    // And the control plane resolved a real identity from the client certificate — proof
    // the mTLS branch ran its full auth path, not merely that TLS completed.
    let last_seen_set: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE last_seen_at IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'acme')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        last_seen_set, 1,
        "heartbeat over the mux should have stamped last_seen_at"
    );
}

/// The agent branch must still demand a client certificate. If ALPN routing accidentally
/// selected the browser config, this connection would succeed — so the assertion is that
/// it fails.
#[tokio::test]
async fn agent_alpn_without_a_client_cert_is_rejected() {
    let s = start().await;

    let mut roots = rustls::RootCertStore::empty();
    for c in parse_certs(&s.mtls_server_cert_pem) {
        roots.add(c).unwrap();
    }
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![fleet_proto::AGENT_ALPN.to_vec()];

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()
        .unwrap();

    let res = client
        .get(format!(
            "https://127.0.0.1:{}/agent/v1/heartbeat",
            s.mux_port
        ))
        .send()
        .await;
    assert!(
        res.is_err(),
        "a certificate-less client on the agent branch must not get a response: {res:?}"
    );
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
