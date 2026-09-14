//! Stopping the listeners on request.
//!
//! Every deployment needs this and only one of them can survive without it: a container or
//! a systemd unit can have the process killed and lose nothing but whatever was in flight,
//! while the Windows service control manager requires an answer — it asks the process to
//! stop and reports a hang if none comes. These tests cover the part that has to work for
//! either: the accept loops leave when the signal fires, and they free the port on the way
//! out rather than lingering as a task nobody is waiting for.
//!
//! `crates/server/src/shutdown.rs` unit-tests the signal itself, and `conn.rs` the drain.
//! What is left, and what is here, is that the listeners are actually wired to them.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fleet_core::aead::MasterKey;
use fleet_server::shutdown;
use tempfile::TempDir;
use tokio::net::TcpStream;

/// Longer than the listeners should ever need, short enough that a listener which ignores
/// the signal fails the test rather than hanging CI until its own timeout.
const STOP_DEADLINE: Duration = Duration::from_secs(20);

struct Harness {
    state: fleet_server::AppState,
    _tempdir: TempDir,
}

async fn harness() -> Harness {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let key_b64 = MasterKey::generate_b64();
    std::env::set_var("MASTER_KEY", &key_b64);
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();

    let cfg = fleet_server::config::Config {
        listen: "127.0.0.1:0".into(),
        listen_https: "127.0.0.1:0".into(),
        listen_mtls: String::new(),
        agent_mtls_url: "https://127.0.0.1:0".into(),
        acme: None,
        tls: None,
        database_path: PathBuf::from(&db_path),
        base_url: "http://127.0.0.1:0".into(),
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
    let trust_store =
        fleet_server::mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem)
            .await
            .unwrap();

    let state = fleet_server::AppState {
        db: db.clone(),
        config: cfg.clone(),
        email: fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap(),
        turnstile: fleet_server::auth::turnstile::Turnstile::from_secret(None),
        rate_limits: fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget),
        agent_limits: fleet_server::agent_limits::AgentRateLimits::new(),
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::new(10_000),
        trust_store,
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    Harness {
        state,
        _tempdir: dir,
    }
}

/// Prove the listener is up by opening a connection, then close it again.
///
/// Closed before the signal fires on purpose: a half-open connection that never sends a
/// ClientHello is held until the handshake deadline, and the drain would then wait it out.
/// That is correct behaviour, and it is not what these tests are timing.
async fn probe(addr: SocketAddr) {
    let stream = TcpStream::connect(addr)
        .await
        .expect("listener should be accepting");
    drop(stream);
    // Give the accept side a moment to notice the peer went away and release its permit.
    tokio::time::sleep(Duration::from_millis(50)).await;
}

async fn refuses_connections(addr: SocketAddr) -> bool {
    TcpStream::connect(addr).await.is_err()
}

#[tokio::test]
async fn the_shared_port_listener_stops_when_the_signal_fires() {
    let h = harness().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (trigger, signal) = shutdown::channel();
    let tls = Arc::new(fleet_server::mux::MuxTls {
        acme_challenge: None,
        web: web_config(),
        agent_sni: None,
    });

    let served = tokio::spawn(fleet_server::mux::serve_on(
        listener,
        tls,
        h.state.trust_store.clone(),
        fleet_server::router(h.state.clone()),
        fleet_server::mtls_router(h.state.clone()),
        signal,
    ));

    probe(addr).await;
    trigger.fire();

    let result = tokio::time::timeout(STOP_DEADLINE, served)
        .await
        .expect("the shared-port listener should return once the signal fires")
        .expect("the listener task should not panic");
    assert!(result.is_ok(), "listener returned an error: {result:?}");

    assert!(
        refuses_connections(addr).await,
        "the port should be free once the listener has returned"
    );
}

#[tokio::test]
async fn the_agent_listener_stops_when_the_signal_fires() {
    let h = harness().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (trigger, signal) = shutdown::channel();
    let served = tokio::spawn(fleet_server::mtls::serve_on(
        listener,
        h.state.trust_store.clone(),
        fleet_server::mtls_router(h.state.clone()),
        signal,
    ));

    probe(addr).await;
    trigger.fire();

    let result = tokio::time::timeout(STOP_DEADLINE, served)
        .await
        .expect("the agent listener should return once the signal fires")
        .expect("the listener task should not panic");
    assert!(result.is_ok(), "listener returned an error: {result:?}");

    assert!(
        refuses_connections(addr).await,
        "the port should be free once the listener has returned"
    );
}

/// A signal that fired before the listener ever started must still stop it, rather than
/// leaving a listener that waits for a transition which already happened.
#[tokio::test]
async fn a_listener_handed_an_already_fired_signal_stops_immediately() {
    let h = harness().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();

    let (trigger, signal) = shutdown::channel();
    trigger.fire();

    let served = fleet_server::mtls::serve_on(
        listener,
        h.state.trust_store.clone(),
        fleet_server::mtls_router(h.state.clone()),
        signal,
    );

    tokio::time::timeout(Duration::from_secs(5), served)
        .await
        .expect("an already-fired signal should stop the listener at once")
        .expect("the listener should return cleanly");
}

use rustls::pki_types::pem::PemObject;

/// A TLS config for the mux's browser branch.
///
/// The certificate only has to be one rustls will accept at build time — what the mux does
/// with it is `mux_flow`'s subject, not this file's. Certificate and key come from the same
/// call, which is the one way to get this wrong.
fn web_config() -> Arc<rustls::ServerConfig> {
    let (cert_pem, key_pem) = fleet_server::mtls::generate_self_signed_server("127.0.0.1").unwrap();
    let certs: Vec<_> = rustls::pki_types::CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(key_pem.as_bytes()).unwrap();
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key.into())
            .unwrap(),
    )
}
