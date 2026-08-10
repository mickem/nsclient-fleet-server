use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use fleet_server::{
    config::Config, ensure_on_prem_admin, mtls, mtls_router, router, tenant_setup::backfill_all,
    AppState,
};

use fleet_server::auth::{email::EmailSender, rate_limit::AuthRateLimits, turnstile::Turnstile};

/// Hostname out of a base URL, dropping scheme, port and path.
fn host_of(base_url: &str) -> String {
    base_url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("localhost")
        .split(':')
        .next()
        .unwrap_or("localhost")
        .to_string()
}

/// The version this binary reports.
///
/// Releases are versioned from git tags, not from `Cargo.toml`, so the release workflow
/// compiles the computed version in through `FLEET_BUILD_VERSION` — otherwise a release
/// named `v0.1.1-rc.7` would contain a binary claiming whatever the manifest last said.
/// A local build has no such variable and falls back to the manifest.
const VERSION: &str = match option_env!("FLEET_BUILD_VERSION") {
    Some(v) => v,
    None => env!("CARGO_PKG_VERSION"),
};

/// Handle the two flags that must work before anything else does. Answered before config
/// is read or the filesystem is touched, so `--version` works on a fresh box with no
/// `MASTER_KEY` set — which is exactly when you want to ask what build you just deployed.
/// Returns true if the process should exit.
fn handled_immediate_flag() -> bool {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("nsclient-fleet {VERSION}");
        return true;
    }
    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!(
            "nsclient-fleet {}\n\n\
             NSClient Fleet — fleet management control plane for NSClient.\n\n\
             Configuration is entirely through environment variables; there are no other\n\
             flags. See docs/deployment.md for the full reference. MASTER_KEY is required.\n\n\
             \x20   --version, -V    print the version and exit\n\
             \x20   --help,    -h    print this message and exit",
            VERSION
        );
        return true;
    }
    false
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    if handled_immediate_flag() {
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cfg = Config::from_env()?;
    if let Some(parent) = Path::new(&cfg.database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }

    tracing::info!(
        version = VERSION,
        db = %cfg.database_path.display(),
        on_prem = cfg.on_prem,
        "starting nsclient-fleet"
    );

    let db = fleet_storage::open(&cfg.database_path).await?;
    let migration_version = fleet_storage::run_migrations(&db.write).await?;
    tracing::info!(migration_version, "migrations applied");

    ensure_on_prem_admin(&db, &cfg).await?;

    // Self-signed cert for agent mTLS, persisted so it survives restarts — agents pin it at
    // enrollment and cannot recover on their own if it changes. Regenerated only when
    // MTLS_HOST no longer matches or expiry is near (logged loudly).
    //
    // The default follows BASE_URL because that is the name agents dial: with agents muxed
    // onto :443 they connect to the same hostname browsers do, and a cert whose SAN says
    // "localhost" would fail their pin check on the first poll.
    let mtls_host = std::env::var("MTLS_HOST").unwrap_or_else(|_| host_of(&cfg.base_url));
    let mtls_state_dir = std::env::var("MTLS_STATE_DIR").unwrap_or_else(|_| "data".into());
    let (mtls_cert_pem, mtls_key_pem) =
        mtls::load_or_generate_server(Path::new(&mtls_state_dir), &mtls_host)?;

    let email = EmailSender::from_config(cfg.smtp.as_ref())?;
    let turnstile = Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = AuthRateLimits::new(cfg.daily_email_budget);
    let agent_limits = fleet_server::agent_limits::AgentRateLimits::new();
    let enrollment_limits = fleet_server::agent_limits::EnrollmentLimits::default();
    let trust_store =
        mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem).await?;

    let bundle_dir = std::env::var("BUNDLE_DIR").unwrap_or_else(|_| "data/bundles".into());
    std::fs::create_dir_all(&bundle_dir)?;
    let bundle_store: Arc<dyn fleet_server::bundles::BundleStore> = Arc::new(
        fleet_server::bundles::LocalBundleStore::new(std::path::PathBuf::from(bundle_dir)),
    );

    let state = AppState {
        db: db.clone(),
        config: cfg.clone(),
        email,
        turnstile,
        rate_limits,
        agent_limits,
        enrollment_limits,
        trust_store: trust_store.clone(),
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store,
        desired_state_cache: Default::default(),
    };

    backfill_all(&state, &db).await?;
    trust_store.rebuild().await?;

    // A dedicated agent port is bound only when LISTEN_MTLS is set (always, when ACME is
    // off). With ACME on and LISTEN_MTLS unset, agents arrive on :443 through the mux and
    // this listener does not exist — one inbound port, no extra firewall rule.
    let mtls_handle = if cfg.listen_mtls.is_empty() {
        None
    } else {
        let mtls_state = state.clone();
        let mtls_addr = cfg.listen_mtls.clone();
        Some(tokio::spawn(async move {
            let r = mtls_router(mtls_state.clone());
            if let Err(e) = mtls::serve(&mtls_addr, mtls_state.trust_store, r).await {
                tracing::error!(error = %e, "mTLS server exited");
            }
        }))
    };

    let agent_app = mtls_router(state.clone());
    let trust_store_for_mux = state.trust_store.clone();
    let app = router(state);

    // `None` unless MTLS_SNI is set: ALPN is the routing key, and a hostname fallback would
    // otherwise send any ALPN-less client (openssl s_client, a bare probe) to the agent
    // branch and greet it with a certificate request. Set it only for a TLS stack that
    // genuinely cannot offer ALPN — and point MTLS_HOST at the same name.
    let agent_sni = std::env::var("MTLS_SNI").ok().filter(|s| !s.is_empty());

    if let Some(acme_cfg) = cfg.acme.clone() {
        // Production: one TLS port carries the operator UI, agent mTLS, and the ACME
        // TLS-ALPN-01 challenge. No :80 listener is needed for issuance.
        let https_addr = cfg.listen_https.clone();
        tracing::info!("ACME enabled — running HTTPS on {https_addr}");
        let serve = fleet_server::https::serve_acme(
            &https_addr,
            acme_cfg,
            app,
            agent_app,
            trust_store_for_mux,
            agent_sni,
        );
        match mtls_handle {
            Some(h) => tokio::select! { r = serve => r?, _ = h => {} },
            None => serve.await?,
        }
    } else {
        let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
        tracing::info!(addr = %cfg.listen, "HTTP listening (no ACME — set ACME_DOMAINS for production)");
        let http = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        );
        match mtls_handle {
            Some(h) => tokio::select! { r = http => r?, _ = h => {} },
            None => http.await?,
        }
    }
    Ok(())
}
