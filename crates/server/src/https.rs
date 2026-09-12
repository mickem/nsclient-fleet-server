//! In-process HTTPS, from Let's Encrypt or from a certificate on disk.
//!
//! Two ways to get a web certificate, and the choice is which one the deployment can
//! actually obtain:
//!
//! - [`serve_acme`] — `ACME_DOMAINS` + `ACME_CONTACT`. Issuance runs on the same port as
//!   normal traffic (TLS-ALPN-01 — no separate :80 listener needed) and state is cached at
//!   `ACME_CACHE_DIR` so restarts don't re-issue (and re-rate-limit you). Needs a publicly
//!   resolvable name and outbound reachability.
//! - [`serve_static`] — `TLS_CERT`/`TLS_KEY`, or `TLS_SELF_SIGNED=true`. For the installs
//!   ACME cannot serve: on-prem, air-gapped, a lab, an IP address with no name at all.
//!
//! Agent mTLS shares the port either way — see `crate::mux` for how the ClientHello selects
//! between the challenge, the agent, and the browser configs. That the two paths differ
//! only in where `MuxTls::web` comes from is the point: on-prem is not a second, lesser
//! serving mode, it is the same mux with a different certificate source.

use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use axum::Router;
use futures_util::StreamExt;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use rustls_acme::{caches::DirCache, AcmeConfig};

use crate::config::{AcmeConfig as Cfg, StaticTlsConfig};
use crate::mtls::MtlsContext;
use crate::mux::{self, MuxTls};

/// ALPN offered on the browser branch, in preference order. rustls-acme sets this for us on
/// the ACME path; the static path has to say it, or every browser falls back to HTTP/1.1.
const WEB_ALPN: [&[u8]; 2] = [b"h2", b"http/1.1"];

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
    // The ACME account key lives here. `UMask=0077` in the unit covers a fresh install, but
    // a directory created by an older version — or by a hand-rolled deployment — keeps
    // whatever mode it was made with, so narrow it every time rather than only on creation.
    crate::restrict_dir(&cfg.cache_dir);

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
        acme_challenge: Some(state.challenge_rustls_config()),
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

/// Run the shared HTTPS/mTLS listener forever with a certificate read from disk.
///
/// The certificate is loaded once, at startup. Renewing it is a restart — the honest trade
/// for having no issuance protocol to hang a reload off, and what an operator who has just
/// replaced a file expects anyway.
pub async fn serve_static(
    addr: &str,
    cfg: StaticTlsConfig,
    web_router: Router,
    agent_router: Router,
    mtls_ctx: MtlsContext,
    agent_sni: Option<String>,
) -> Result<()> {
    if cfg.is_self_signed() {
        ensure_self_signed(&cfg)?;
    }

    let web = load_server_config(&cfg.cert_path, &cfg.key_path)?;

    let tls = Arc::new(MuxTls {
        acme_challenge: None,
        web: Arc::new(web),
        agent_sni,
    });

    tracing::info!(
        addr = %addr,
        cert = %cfg.cert_path.display(),
        self_signed = cfg.is_self_signed(),
        "HTTPS listening (certificate from disk)"
    );
    mux::serve(addr, tls, mtls_ctx, web_router, agent_router).await
}

/// Generate and persist the web certificate if it is not already there and usable.
///
/// Deliberately not the same file as the agent's `mtls-server.crt`. Agents pin theirs and
/// cannot recover if it changes, so it has to stay put for years; the web certificate is the
/// one an operator replaces the moment they have a real CA, and regenerating it costs
/// nothing but a browser warning. Sharing one file would drag the first property onto a file
/// that has the second's lifecycle.
fn ensure_self_signed(cfg: &StaticTlsConfig) -> Result<()> {
    if cfg.cert_path.exists() && cfg.key_path.exists() {
        match self_signed_still_valid(&cfg.cert_path) {
            Ok(()) => {
                tracing::info!(
                    path = %cfg.cert_path.display(),
                    "reusing persisted self-signed web certificate"
                );
                return Ok(());
            }
            Err(reason) => tracing::warn!(
                %reason,
                path = %cfg.cert_path.display(),
                "persisted web certificate unusable — regenerating. Browsers that were given \
                 an exception for the old one will warn again."
            ),
        }
    }

    if let Some(dir) = cfg.cert_path.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let (cert_pem, key_pem) = crate::mtls::generate_self_signed(&cfg.self_signed_hosts)?;
    std::fs::write(&cfg.cert_path, &cert_pem)
        .with_context(|| format!("write {}", cfg.cert_path.display()))?;
    crate::mtls::write_key_restricted(&cfg.key_path, &key_pem)?;
    tracing::info!(
        path = %cfg.cert_path.display(),
        hosts = ?cfg.self_signed_hosts,
        "generated a self-signed web certificate — browsers warn until its issuer is trusted"
    );
    Ok(())
}

/// A generated certificate is reused until it is close enough to expiry to matter.
///
/// Only expiry is checked, not the SAN list: unlike the agent certificate, nothing pins this
/// one, so an operator who wants a different name edits `TLS_HOSTS` and deletes the file.
/// Regenerating on every `BASE_URL` tweak would churn browser exceptions for no gain.
fn self_signed_still_valid(cert_path: &Path) -> std::result::Result<(), String> {
    let pem = std::fs::read_to_string(cert_path).map_err(|e| format!("unreadable: {e}"))?;
    crate::mtls::cert_valid_for_at_least(&pem, 30 * 86_400)
}

/// Build a rustls config from a PEM certificate chain and private key.
fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<ServerConfig> {
    let cert_pem = std::fs::read(cert_path).with_context(|| {
        format!(
            "read TLS certificate {} — point TLS_CERT at a readable PEM file, or set \
             TLS_SELF_SIGNED=true to have one generated",
            cert_path.display()
        )
    })?;
    let key_pem =
        std::fs::read(key_path).with_context(|| format!("read TLS key {}", key_path.display()))?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_pem.as_slice()).collect::<std::result::Result<_, _>>()?;
    if certs.is_empty() {
        bail!(
            "{} contains no CERTIFICATE block — is it the key file, or DER rather than PEM?",
            cert_path.display()
        );
    }

    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut key_pem.as_slice())?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{} contains no private key — expected a PKCS#8, PKCS#1 or SEC1 PEM block",
                key_path.display()
            )
        })?;

    let mut config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .with_context(|| {
            format!(
                "{} and {} are not a matching certificate and key",
                cert_path.display(),
                key_path.display()
            )
        })?;
    config.alpn_protocols = WEB_ALPN.iter().map(|p| p.to_vec()).collect();
    Ok(config)
}
