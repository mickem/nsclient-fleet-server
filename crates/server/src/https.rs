//! In-process HTTPS via Let's Encrypt (TLS-ALPN-01) using `rustls-acme`.
//!
//! Activated when `ACME_DOMAINS` + `ACME_CONTACT` are set. The challenge runs on the same
//! port as normal traffic (TLS-ALPN-01 — no separate :80 listener needed). State is cached
//! at `ACME_CACHE_DIR` so restarts don't re-issue (and re-rate-limit you).
//!
//! Agent mTLS shares this port too — see `crate::mux` for how the ClientHello selects
//! between the challenge, the agent, and the browser configs.

use std::sync::Arc;

use anyhow::{Context, Result};
use axum::Router;
use futures_util::StreamExt;
use rustls_acme::{caches::DirCache, AcmeConfig};

use crate::config::AcmeConfig as Cfg;
use crate::mtls::MtlsContext;
use crate::mux::{self, MuxTls};

/// Run the shared HTTPS/mTLS listener forever, terminating TLS for `cfg.domains` via
/// Let's Encrypt and routing agent connections to `agent_router`.
pub async fn serve_acme(
    addr: &str,
    cfg: Cfg,
    web_router: Router,
    agent_router: Router,
    mtls_ctx: MtlsContext,
    agent_sni: Option<String>,
) -> Result<()> {
    tokio::fs::create_dir_all(&cfg.cache_dir)
        .await
        .with_context(|| format!("create acme cache dir {}", cfg.cache_dir.display()))?;

    let directory = if cfg.production {
        rustls_acme::acme::LETS_ENCRYPT_PRODUCTION_DIRECTORY
    } else {
        rustls_acme::acme::LETS_ENCRYPT_STAGING_DIRECTORY
    };

    let mut state = AcmeConfig::new(cfg.domains.iter().cloned())
        .contact_push(format!("mailto:{}", cfg.contact_email))
        .cache(DirCache::new(cfg.cache_dir.clone()))
        .directory(directory)
        .state();

    // Snapshot both configs before the state machine moves into its drain task. Each holds
    // an `Arc<ResolvesServerCertAcme>` pointing at the same live resolver, so certificates
    // issued later are picked up by connections accepted later — no restart needed.
    let tls = Arc::new(MuxTls {
        acme_challenge: state.challenge_rustls_config(),
        web: state.default_rustls_config(),
        agent_sni,
    });

    // Drain the ACME state machine in the background — without this, certificate issuance
    // never makes progress.
    tokio::spawn(async move {
        while let Some(event) = state.next().await {
            match event {
                Ok(ok) => tracing::info!(?ok, "acme event"),
                Err(err) => tracing::error!(?err, "acme error"),
            }
        }
    });

    tracing::info!(addr = %addr, domains = ?cfg.domains, production = cfg.production, "HTTPS listening (acme)");
    mux::serve(addr, tls, mtls_ctx, web_router, agent_router).await
}

/// Sentinel for callers that want to know whether to use ACME at startup.
pub fn enabled(state: &Arc<crate::AppState>) -> bool {
    state.config.acme.is_some()
}
