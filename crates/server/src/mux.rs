//! Single-port TLS mux — the operator UI, agent mTLS, and ACME challenges share `:443`.
//!
//! Two listeners cannot bind one port, but TLS gives us a decision point *before* a
//! `ServerConfig` is committed: the ClientHello. `LazyConfigAcceptor` parses it, we read
//! ALPN (and SNI as a fallback), and only then hand the handshake the config it needs.
//!
//! Three branches, each keeping the TLS parameters it had when it owned its own port:
//!
//! | ClientHello                  | config                          | served by      |
//! | ---------------------------- | ------------------------------- | -------------- |
//! | ALPN `acme-tls/1`            | ACME challenge (throwaway cert) | nothing — handshake only |
//! | ALPN `nsclient-fleet/1`, or agent SNI  | mTLS: client cert **required**, pinned self-signed cert | agent router |
//! | anything else                | ACME cert, no client cert asked | operator router |
//!
//! Why the agent branch keeps its own self-signed cert rather than sharing the ACME one:
//! agents pin `mtls_server_cert_pem` from their enroll response and trust nothing else, so
//! agent connectivity stays independent of ACME succeeding. That matters on-prem and it
//! means a Let's Encrypt outage can't strand a fleet.
//!
//! Why not one config with optional client auth: rustls puts the DN of every trusted root
//! in the CertificateRequest, so a shared config would broadcast every tenant CA's DN to
//! anyone who opens the login page — and browsers would prompt for a certificate.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use axum::extract::ConnectInfo;
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use rustls::server::Acceptor;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::LazyConfigAcceptor;
use tower::Service;

use crate::mtls::{self, MtlsContext, AGENT_ALPN};

const ACME_ALPN: &[u8] = b"acme-tls/1";

/// TLS configs for the two non-agent branches, plus the optional SNI fallback.
pub struct MuxTls {
    /// Serves the TLS-ALPN-01 challenge certificate. From `AcmeState::challenge_rustls_config`.
    pub acme_challenge: Arc<ServerConfig>,
    /// Serves the real certificate to browsers. From `AcmeState::default_rustls_config`.
    pub web: Arc<ServerConfig>,
    /// Hostname that also routes to the agent branch when a client sends no ALPN.
    /// Belt-and-braces for a TLS stack that can't set ALPN; `None` disables it.
    pub agent_sni: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Branch {
    Acme,
    Agent,
    Web,
}

/// Pick a branch from the ClientHello. Pure so it can be tested without a socket.
fn classify(alpn: &[Vec<u8>], server_name: Option<&str>, agent_sni: Option<&str>) -> Branch {
    if alpn.iter().any(|p| p == ACME_ALPN) {
        return Branch::Acme;
    }
    if alpn.iter().any(|p| p == AGENT_ALPN) {
        return Branch::Agent;
    }
    // SNI fallback only when the client offered no ALPN at all. A browser that negotiated
    // h2/http1.1 must never land on the agent branch even if it dialled the agent name.
    match (alpn.is_empty(), agent_sni, server_name) {
        (true, Some(want), Some(got)) if got.eq_ignore_ascii_case(want) => Branch::Agent,
        _ => Branch::Web,
    }
}

/// Accept forever on `addr`, dispatching each connection by its ClientHello.
pub async fn serve(
    addr: &str,
    tls: Arc<MuxTls>,
    mtls_ctx: MtlsContext,
    web_router: Router,
    agent_router: Router,
) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(
        addr = %addr,
        agent_alpn = %String::from_utf8_lossy(AGENT_ALPN),
        agent_sni = ?tls.agent_sni,
        "shared-port listener up (operator UI + agent mTLS + ACME)"
    );
    serve_on(listener, tls, mtls_ctx, web_router, agent_router).await
}

/// As [`serve`], on an already-bound listener — see [`crate::mtls::serve_on`] for why
/// callers that need the port up front must not bind, drop, and re-bind.
pub async fn serve_on(
    listener: TcpListener,
    tls: Arc<MuxTls>,
    mtls_ctx: MtlsContext,
    web_router: Router,
    agent_router: Router,
) -> Result<()> {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let tls = tls.clone();
        let snapshot = mtls_ctx.snapshot();
        let web_router = web_router.clone();
        let agent_router = agent_router.clone();
        tokio::spawn(async move {
            let r = handle_conn(stream, peer_addr, tls, snapshot, web_router, agent_router).await;
            if let Err(e) = r {
                tracing::debug!(error = %e, ip = %peer_addr.ip(), "muxed conn ended");
            }
        });
    }
}

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    tls: Arc<MuxTls>,
    mtls_state: Arc<crate::mtls::MtlsState>,
    web_router: Router,
    agent_router: Router,
) -> Result<()> {
    let start = match LazyConfigAcceptor::new(Acceptor::default(), stream).await {
        Ok(s) => s,
        Err(e) => {
            // Port scanners and plain-HTTP-to-443 mistakes both land here.
            tracing::debug!(ip = %peer_addr.ip(), error = %e, "no usable ClientHello");
            return Ok(());
        }
    };

    // Scope the borrow: `client_hello()` borrows `start`, which `into_stream` consumes.
    let branch = {
        let hello = start.client_hello();
        let alpn: Vec<Vec<u8>> = hello
            .alpn()
            .map(|it| it.map(|p| p.to_vec()).collect())
            .unwrap_or_default();
        classify(&alpn, hello.server_name(), tls.agent_sni.as_deref())
    };

    match branch {
        Branch::Acme => {
            // Completing the handshake *is* the challenge response. Let's Encrypt reads the
            // certificate we present and hangs up; there is no application data.
            match start.into_stream(tls.acme_challenge.clone()).await {
                Ok(_) => tracing::info!(ip = %peer_addr.ip(), "served TLS-ALPN-01 challenge"),
                Err(e) => {
                    tracing::warn!(ip = %peer_addr.ip(), error = %e, "TLS-ALPN-01 handshake failed")
                }
            }
            Ok(())
        }
        Branch::Agent => {
            let stream = match start.into_stream(mtls_state.tls_config.clone()).await {
                Ok(s) => s,
                Err(e) => {
                    mtls::log_handshake_failure(&e, peer_addr.ip());
                    return Ok(());
                }
            };
            mtls::serve_tls_conn(stream, peer_addr, mtls_state, agent_router).await
        }
        Branch::Web => {
            let stream = match start.into_stream(tls.web.clone()).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::debug!(ip = %peer_addr.ip(), error = %e, "web handshake failed");
                    return Ok(());
                }
            };
            serve_web(stream, peer_addr, web_router).await
        }
    }
}

/// Run the operator router over an established TLS connection.
///
/// Inserts `ConnectInfo` explicitly. The auth handlers extract it to rate-limit by IP
/// (`auth/handlers.rs`), and unlike `axum::serve(..).into_make_service_with_connect_info()`
/// nothing adds it for us here.
async fn serve_web(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    router: Router,
) -> Result<()> {
    let io = TokioIo::new(tls);
    let svc_fn = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        let mut svc = router.clone().into_service::<Incoming>();
        req.extensions_mut().insert(ConnectInfo(peer_addr));
        async move { svc.call(req).await }
    });

    HttpBuilder::new(hyper_util::rt::TokioExecutor::new())
        .serve_connection(io, svc_fn)
        .await
        .map_err(|e| anyhow!("http: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &[u8]) -> Vec<u8> {
        s.to_vec()
    }

    #[test]
    fn acme_challenge_wins_over_everything() {
        assert_eq!(
            classify(
                &[v(ACME_ALPN), v(AGENT_ALPN)],
                Some("agents.x.io"),
                Some("agents.x.io")
            ),
            Branch::Acme
        );
    }

    #[test]
    fn agent_alpn_routes_to_agent() {
        assert_eq!(classify(&[v(AGENT_ALPN)], None, None), Branch::Agent);
        // Offered alongside the usual HTTP protocols — still an agent.
        assert_eq!(
            classify(&[v(b"h2"), v(b"http/1.1"), v(AGENT_ALPN)], None, None),
            Branch::Agent
        );
    }

    #[test]
    fn browsers_route_to_web() {
        assert_eq!(
            classify(&[v(b"h2"), v(b"http/1.1")], Some("app.x.io"), None),
            Branch::Web
        );
        assert_eq!(
            classify(&[], Some("app.x.io"), Some("agents.x.io")),
            Branch::Web
        );
    }

    #[test]
    fn sni_fallback_only_applies_without_alpn() {
        assert_eq!(
            classify(&[], Some("agents.x.io"), Some("agents.x.io")),
            Branch::Agent
        );
        assert_eq!(
            classify(&[], Some("AGENTS.X.IO"), Some("agents.x.io")),
            Branch::Agent,
            "SNI comparison is case-insensitive"
        );
        // A browser dialling the agent hostname must still get the web branch, or it would
        // be asked for a client certificate.
        assert_eq!(
            classify(
                &[v(b"h2"), v(b"http/1.1")],
                Some("agents.x.io"),
                Some("agents.x.io")
            ),
            Branch::Web
        );
    }

    #[test]
    fn no_sni_and_no_alpn_is_web() {
        assert_eq!(classify(&[], None, Some("agents.x.io")), Branch::Web);
    }
}
