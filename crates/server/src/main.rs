mod cli;
#[cfg(windows)]
mod service;

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use fleet_server::{
    config::Config, ensure_on_prem_admin, ensure_platform_admins, mtls, mtls_router, router,
    shutdown::Shutdown, tenant_setup::backfill_all, AppState,
};

use fleet_server::auth::{email::EmailSender, rate_limit::AuthRateLimits, turnstile::Turnstile};
use fleet_server::config::host_of;

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

/// Everything the process does before it is a server: answer a flag, print a hash, or
/// register a service. See [`cli`] for the argument parsing itself.
///
/// Answered before config is read or the filesystem is touched, so `--version` works on a
/// fresh box with no `MASTER_KEY` set — which is exactly when you want to ask what build
/// you just deployed.
fn handled_immediate_command(args: &cli::Args) -> anyhow::Result<bool> {
    match args.command {
        cli::Command::Version => {
            println!("nsclient-fleet {VERSION}");
            Ok(true)
        }
        cli::Command::Help => {
            print!("{}", cli::help(VERSION));
            Ok(true)
        }
        cli::Command::HashPassword => {
            println!("{}", cli::hash_password_interactively()?);
            Ok(true)
        }
        #[cfg(windows)]
        cli::Command::ServiceInstall => {
            service::install(args)?;
            Ok(true)
        }
        #[cfg(windows)]
        cli::Command::ServiceUninstall => {
            service::uninstall()?;
            Ok(true)
        }
        cli::Command::Serve => Ok(false),
    }
}

fn main() -> anyhow::Result<()> {
    let args = cli::Args::parse(std::env::args().skip(1))?;
    if handled_immediate_command(&args)? {
        return Ok(());
    }

    // Before anything reads the environment. On Windows this is how a service gets its
    // configuration at all — see `crate::service` and `fleet_server::env_file`.
    let from_file = match &args.env_file {
        Some(path) => fleet_server::env_file::load(path)?,
        None => Vec::new(),
    };

    // Held for the rest of the process: dropping it stops the log file being written.
    let _log_guard = init_tracing();

    // Under the Windows service control manager this never returns until the service is
    // stopped. Anywhere else — a console, a container, systemd — it reports that there is
    // no SCM to talk to and we carry on as an ordinary foreground process.
    #[cfg(windows)]
    if service::run_if_started_by_scm(&from_file)? {
        return Ok(());
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let (trigger, shutdown) = fleet_server::shutdown::channel();
        tokio::spawn(async move {
            wait_for_signal().await;
            tracing::info!("shutdown signal received");
            trigger.fire();
        });
        serve(shutdown, &from_file).await
    })
}

/// Install the log subscriber. Called once, from `main`, before anything that logs.
///
/// Logs go to stdout, which is what journald, `docker logs` and a console all read. A
/// Windows service has none of those — the service control manager starts the process with
/// no console and discards stdout entirely — so `LOG_FILE` sends them to a file instead,
/// rotated daily. That is the only way a service that fails at startup says why.
///
/// The returned guard flushes the file writer when it is dropped, so `main` has to hold it
/// until the process is done; there is nothing to hold when logging to stdout.
#[must_use = "dropping the guard stops the log file being written"]
fn init_tracing() -> Option<tracing_appender::non_blocking::WorkerGuard> {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    let path = std::env::var("LOG_FILE")
        .ok()
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from);

    let Some(path) = path else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
        return None;
    };

    // Nothing is logging yet, so a failure here has to say so on stderr and fall back —
    // refusing to start because the log file is unwritable would be a worse trade than
    // starting with the logs somewhere less convenient.
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!(
                "could not create the LOG_FILE directory {}: {e}",
                dir.display()
            );
            tracing_subscriber::fmt().with_env_filter(filter).init();
            return None;
        }
        fleet_server::restrict_dir(dir);
    }
    let Some(name) = path.file_name() else {
        eprintln!(
            "LOG_FILE {} names no file; logging to stdout",
            path.display()
        );
        tracing_subscriber::fmt().with_env_filter(filter).init();
        return None;
    };

    // `daily` appends the date to the name, so LOG_FILE names the series rather than one
    // file: `fleet.log` becomes `fleet.log.2026-09-13`.
    let appender = tracing_appender::rolling::daily(dir.unwrap_or(std::path::Path::new(".")), name);
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        // A log file is read with a text editor, not a terminal: colour codes in it are
        // noise at best.
        .with_ansi(false)
        .with_writer(writer)
        .init();
    Some(guard)
}

/// Resolve on the first request to stop that the host platform can make.
///
/// Ctrl-C everywhere; SIGTERM as well on unix, which is what `systemctl stop` and a
/// container runtime both send and what the unit's `TimeoutStopSec` is counting against.
async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not listen for SIGTERM; Ctrl-C only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows;
        // Ctrl-C is the one everybody thinks of, and on its own it leaves the two ways a
        // console session actually ends unhandled: Ctrl-Break, and the window being
        // closed. CTRL_CLOSE_EVENT is the interesting one — Windows gives a process a few
        // seconds after it before killing the process tree, which is enough to drain, and
        // without a handler the process is simply gone mid-request.
        //
        // A service never reaches any of this: the SCM's stop request arrives through the
        // control handler in `crate::service`.
        let mut break_ = match windows::ctrl_break() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not listen for Ctrl-Break");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        let mut close = match windows::ctrl_close() {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(error = %e, "could not listen for the console closing");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = break_.recv() => {}
            _ = close.recv() => {}
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Start every listener and run until `shutdown` fires.
///
/// `env_file_vars` is only for the startup log: which settings came from a file rather
/// than the environment is the first thing to check when a service starts with the wrong
/// configuration, and on Windows it is not visible any other way.
async fn serve(shutdown: Shutdown, env_file_vars: &[String]) -> anyhow::Result<()> {
    if !env_file_vars.is_empty() {
        // Names only, never values — the whole point of the file is that it holds the ones
        // that must not be logged. Which settings came from it is the first thing to check
        // when a service starts with configuration nobody recognises.
        tracing::info!(vars = ?env_file_vars, "loaded settings from --env-file");
    }

    let cfg = Config::from_env()?;
    if let Some(parent) = Path::new(&cfg.database_path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
            fleet_server::restrict_dir(parent);
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
    ensure_platform_admins(&db, &cfg).await?;

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
    // On-prem has no self-service signup at all, so there is nothing to protect. Anywhere
    // else, an open signup form with no challenge is a standing invitation to script it —
    // the rate limiter caps the damage but does not stop it, so say so at a level an
    // operator will actually see rather than hiding it in the Turnstile constructor.
    if cfg.turnstile_secret.is_none() && !cfg.on_prem {
        tracing::warn!(
            "TURNSTILE_SECRET and TURNSTILE_SITE_KEY are unset — self-service signup has no              bot challenge. Set both for any deployment reachable from the internet, or set              ON_PREM=true, or close signups from the platform console."
        );
    }
    let rate_limits = AuthRateLimits::new(cfg.daily_email_budget);
    let agent_limits = fleet_server::agent_limits::AgentRateLimits::new();
    let enrollment_limits = fleet_server::agent_limits::EnrollmentLimits::default();
    let trust_store =
        mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem).await?;

    let bundle_dir = std::env::var("BUNDLE_DIR").unwrap_or_else(|_| "data/bundles".into());
    std::fs::create_dir_all(&bundle_dir)?;
    // Bundles can carry scripts and, in the plain format, secrets. Same reasoning as the
    // ACME cache: the unit's UMask covers new files, this covers a directory that already
    // exists with a wider mode.
    fleet_server::restrict_dir(std::path::Path::new(&bundle_dir));
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

    // Both cleanups existed and neither was ever called, so these two tables only grew.
    tokio::spawn(fleet_server::housekeeping::run(
        db.clone(),
        cfg.session_idle_ttl_secs,
    ));

    backfill_all(&state, &db).await?;
    fleet_server::tenant_setup::rebind_legacy_ciphertexts(&state, &db).await?;
    fleet_server::tenant_setup::resign_bundles(&state, &db).await?;
    trust_store.rebuild().await?;

    // A dedicated agent port is bound only when LISTEN_MTLS is set (always, when ACME is
    // off). With ACME on and LISTEN_MTLS unset, agents arrive on :443 through the mux and
    // this listener does not exist — one inbound port, no extra firewall rule.
    let mtls_handle = if cfg.listen_mtls.is_empty() {
        None
    } else {
        let mtls_state = state.clone();
        let mtls_addr = cfg.listen_mtls.clone();
        let mtls_shutdown = shutdown.clone();
        Some(tokio::spawn(async move {
            let r = mtls_router(mtls_state.clone());
            if let Err(e) = mtls::serve(&mtls_addr, mtls_state.trust_store, r, mtls_shutdown).await
            {
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
            shutdown,
        );
        run_until_stopped(serve, mtls_handle).await?
    } else if let Some(tls_cfg) = cfg.tls.clone() {
        // Same mux as the ACME branch, same single port — only the certificate's origin
        // differs. This is the path for a deployment Let's Encrypt cannot reach.
        let https_addr = cfg.listen_https.clone();
        let serve = fleet_server::https::serve_static(
            &https_addr,
            tls_cfg,
            app,
            agent_app,
            trust_store_for_mux,
            agent_sni,
            shutdown,
        );
        run_until_stopped(serve, mtls_handle).await?
    } else {
        let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
        tracing::info!(addr = %cfg.listen, "HTTP listening (no ACME — set ACME_DOMAINS for production)");
        // The one listener axum serves directly, so it is also the one place its own
        // graceful shutdown applies; the TLS listeners are our accept loops and stop
        // through the same signal in `crate::mux` and `crate::mtls`.
        let http = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.wait());
        run_until_stopped(
            async move { http.await.map_err(anyhow::Error::from) },
            mtls_handle,
        )
        .await?
    }
    tracing::info!("stopped");
    Ok(())
}

/// Run the web listener, and the dedicated agent listener when there is one, until either
/// stops.
///
/// On a shutdown both stop, but not at the same instant — each drains whatever it was
/// serving. Whichever finishes first, the other is given until its own drain deadline to
/// finish too, so a stop does not cut short an agent's renewal just because the operator
/// UI had nothing in flight. If the agent listener is the one that exited first, it failed
/// and has already said so: there is no recovery for a listener that is gone, so the
/// process stops rather than serving half a fleet in silence.
async fn run_until_stopped(
    serve: impl std::future::Future<Output = anyhow::Result<()>>,
    mtls_handle: Option<tokio::task::JoinHandle<()>>,
) -> anyhow::Result<()> {
    let Some(handle) = mtls_handle else {
        return serve.await;
    };

    tokio::pin!(serve);
    tokio::pin!(handle);
    // Which branch won has to be recorded rather than inferred: awaiting a `JoinHandle`
    // that has already resolved panics, so the wait below must not happen in the case
    // where the agent listener is what ended the select.
    let mut agent_listener_finished = false;
    let result = tokio::select! {
        r = &mut serve => r,
        _ = &mut handle => {
            agent_listener_finished = true;
            Ok(())
        }
    };

    if !agent_listener_finished {
        // A second of headroom over the drain itself, so the deadline that decides the
        // outcome is the listener's own rather than this one.
        let grace = fleet_server::shutdown::DRAIN_TIMEOUT + std::time::Duration::from_secs(1);
        if tokio::time::timeout(grace, handle).await.is_err() {
            tracing::warn!("agent listener did not finish draining; exiting anyway");
        }
    }
    result
}
