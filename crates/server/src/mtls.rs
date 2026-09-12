use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use axum::Router;
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use std::sync::RwLock;
use tokio::net::TcpListener;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tower::Service;
use x509_parser::prelude::FromDer;

use crate::conn::{http_builder, ConnLimit, HANDSHAKE_TIMEOUT};
use fleet_storage::{Db, TenantSecretsRepo};

#[derive(Clone, Debug)]
pub struct PeerHostContext {
    pub tenant_id: i64,
    pub tenant_slug: String,
    pub host_id: String,
    pub serial_hex: String,
}

/// ALPN protocol the agent offers so a shared-port listener can route it to the mTLS
/// branch without needing a dedicated port or a second hostname. See `crate::mux`.
pub use fleet_proto::AGENT_ALPN;

pub(crate) struct MtlsState {
    pub(crate) tls_config: Arc<ServerConfig>,
    /// Keyed by the **raw DER** of the CA's subject, not a printed-and-canonicalised
    /// string. Two tenants whose subjects differ only in whitespace or case printed the
    /// same under the old canonicalisation, and resolution was `find` over a hash map —
    /// first hit wins, in whatever order the map happened to iterate. A tenant could
    /// therefore be resolved to the wrong one and refused on the SAN cross-check, which is
    /// a cross-tenant outage triggered by naming a tenant. DER is what the certificate
    /// actually carries; comparing it needs no normalisation to get wrong.
    tenant_by_issuer_der: HashMap<Vec<u8>, (i64, String)>,
}

impl MtlsState {
    fn trusts_tenant(&self, tenant_id: i64) -> bool {
        self.tenant_by_issuer_der
            .values()
            .any(|(id, _)| *id == tenant_id)
    }
}

#[derive(Clone)]
pub struct MtlsContext {
    state: Arc<RwLock<Arc<MtlsState>>>,
    db: Db,
    server_cert_pem: Arc<String>,
    server_key_pem: Arc<String>,
}

impl MtlsContext {
    pub async fn load(db: Db, server_cert_pem: String, server_key_pem: String) -> Result<Self> {
        // Install the rustls default CryptoProvider once for the process.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let st = build_state(&db, &server_cert_pem, &server_key_pem).await?;
        Ok(Self {
            state: Arc::new(RwLock::new(Arc::new(st))),
            db,
            server_cert_pem: Arc::new(server_cert_pem),
            server_key_pem: Arc::new(server_key_pem),
        })
    }

    pub async fn rebuild(&self) -> Result<()> {
        let st = build_state(&self.db, &self.server_cert_pem, &self.server_key_pem).await?;
        *self.state.write().expect("trust store lock") = Arc::new(st);
        Ok(())
    }

    /// Fire-and-forget rebuild, for changes where no caller is waiting on the result.
    ///
    /// Do **not** use this to make a tenant's CA usable — the spawned task can land after
    /// the response that told a client to start using a certificate signed by it. Use
    /// [`Self::ensure_tenant_trusted`] for that.
    pub fn notify_change(&self) {
        let me = self.clone();
        tokio::spawn(async move {
            if let Err(e) = me.rebuild().await {
                tracing::error!(error = %e, "mTLS trust store rebuild failed");
            } else {
                tracing::info!("mTLS trust store reloaded");
            }
        });
    }

    /// Is this tenant's CA currently in the trust store?
    pub fn trusts_tenant(&self, tenant_id: i64) -> bool {
        self.snapshot().trusts_tenant(tenant_id)
    }

    /// Guarantee the tenant's CA is loaded before returning, rebuilding if it is not.
    ///
    /// Enrollment hands a host a certificate and immediately tells it to open an mTLS
    /// connection. If the issuing CA is not in the verifier's root store by then, rustls
    /// aborts the handshake with `UnknownCA` and the server logs "not signed by any known
    /// tenant CA — re-enroll the host", which is misleading: the enrollment is fine, the
    /// trust store is simply behind. A brand-new tenant hits this every time, because its
    /// CA reaches the trust store only via a rebuild triggered at first enrollment.
    ///
    /// Cheap in the common case — an in-memory check — so it costs a rebuild only on the
    /// first enrollment for a tenant, or after the CA is rotated.
    pub async fn ensure_tenant_trusted(&self, tenant_id: i64) -> Result<()> {
        if self.trusts_tenant(tenant_id) {
            return Ok(());
        }
        self.rebuild().await?;
        if !self.trusts_tenant(tenant_id) {
            return Err(anyhow!(
                "tenant {tenant_id} CA still absent from the trust store after a rebuild"
            ));
        }
        tracing::info!(tenant_id, "mTLS trust store now carries this tenant's CA");
        Ok(())
    }

    pub(crate) fn snapshot(&self) -> Arc<MtlsState> {
        self.state.read().expect("trust store lock").clone()
    }
}

async fn build_state(db: &Db, server_cert_pem: &str, server_key_pem: &str) -> Result<MtlsState> {
    let secrets = TenantSecretsRepo::new(db);
    let cas = secrets.list_all_cas().await?;

    let mut roots = RootCertStore::empty();
    let mut tenant_by_issuer_der: HashMap<Vec<u8>, (i64, String)> = HashMap::new();
    for ca in &cas {
        let der = parse_first_cert_pem(&ca.ca_cert_pem)
            .with_context(|| format!("ca pem for tenant {}", ca.tenant_id))?;
        let subject_der = ca_subject_der(&der)
            .with_context(|| format!("ca subject for tenant {}", ca.tenant_id))?;

        // Two tenants cannot share a CA subject: slugs are unique and validated, so this
        // is a bug or a hand-edited database rather than something a user can cause. Refuse
        // both rather than picking one — resolving a leaf to the wrong tenant is worse than
        // refusing it, and taking the whole rebuild down would strand every other tenant.
        if let Some((other_id, _)) = tenant_by_issuer_der.get(&subject_der) {
            tracing::error!(
                tenant_id = ca.tenant_id,
                other_tenant_id = other_id,
                subject_dn = %ca.ca_subject_dn,
                "two tenants share a CA subject — neither will be trusted until this is resolved"
            );
            tenant_by_issuer_der.remove(&subject_der);
            continue;
        }

        roots
            .add(CertificateDer::from(der))
            .with_context(|| format!("add ca for tenant {}", ca.tenant_id))?;
        tenant_by_issuer_der.insert(subject_der, (ca.tenant_id, ca.tenant_slug.clone()));
    }

    let server_certs = parse_all_cert_pem(server_cert_pem)?
        .into_iter()
        .map(CertificateDer::from)
        .collect::<Vec<_>>();
    let server_key = parse_first_pkcs8_key_pem(server_key_pem)?;

    // WebPkiClientVerifier::builder rejects empty root stores. When no tenants exist yet,
    // seed the trust store with the server's own cert as a placeholder — no real client
    // will ever present a leaf signed by it. The store gets rebuilt with actual tenant CAs
    // on the first tenant_setup::ensure_secrets call.
    if cas.is_empty() {
        for cert in &server_certs {
            roots.add(cert.clone()).ok();
        }
    }

    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow!("verifier build: {e}"))?;

    let mut cfg = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(server_certs, PrivatePkcs8KeyDer::from(server_key).into())
        .map_err(|e| anyhow!("server config: {e}"))?;

    // Advertise both, in server-preference order. An agent that offers `nsclient-fleet/1` negotiates
    // it (and is therefore routable by the shared-port mux); a client that offers only
    // `http/1.1` — anything hitting a dedicated LISTEN_MTLS port — still connects. Leaving
    // this list empty would be fine for the dedicated port but would make rustls reject
    // ALPN-offering agents on the mux with `no_application_protocol`.
    cfg.alpn_protocols = vec![AGENT_ALPN.to_vec(), b"http/1.1".to_vec()];

    Ok(MtlsState {
        tls_config: Arc::new(cfg),
        tenant_by_issuer_der,
    })
}

fn parse_all_cert_pem(pem: &str) -> Result<Vec<Vec<u8>>> {
    let mut out = Vec::new();
    let mut rest = pem.as_bytes();
    while let Some((item, remaining)) =
        rustls_pemfile::read_one_from_slice(rest).map_err(|e| anyhow!("pem parse: {e:?}"))?
    {
        rest = remaining;
        if let rustls_pemfile::Item::X509Certificate(c) = item {
            out.push(c.to_vec());
        }
    }
    if out.is_empty() {
        Err(anyhow!("no certificates in PEM"))
    } else {
        Ok(out)
    }
}

fn parse_first_cert_pem(pem: &str) -> Result<Vec<u8>> {
    parse_all_cert_pem(pem)?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("empty cert pem"))
}

fn parse_first_pkcs8_key_pem(pem: &str) -> Result<Vec<u8>> {
    let mut rest = pem.as_bytes();
    while let Some((item, remaining)) =
        rustls_pemfile::read_one_from_slice(rest).map_err(|e| anyhow!("pem parse: {e:?}"))?
    {
        rest = remaining;
        if let rustls_pemfile::Item::Pkcs8Key(k) = item {
            return Ok(k.secret_pkcs8_der().to_vec());
        }
    }
    Err(anyhow!("no pkcs8 private key in PEM"))
}

pub async fn serve(addr: &str, ctx: MtlsContext, router: Router) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(addr = %addr, "mTLS listening");
    serve_on(listener, ctx, router).await
}

/// As [`serve`], but on a listener the caller already bound.
///
/// Callers that need to know the port before starting — tests binding `:0` — must use this
/// rather than binding, reading `local_addr`, dropping, and letting `serve` re-bind. That
/// pattern leaves a window in which anything else can take the port, and when the thief is
/// another mTLS server the symptom is a TLS trust failure (`UnknownCA`, from a trust store
/// belonging to someone else) rather than anything resembling a port collision.
pub async fn serve_on(listener: TcpListener, ctx: MtlsContext, router: Router) -> Result<()> {
    let limit = ConnLimit::new("agent-mtls");
    loop {
        // Taken before `accept` — see `crate::conn::ConnLimit` for why the backpressure
        // belongs in the kernel backlog rather than in an accept-then-drop.
        let permit = limit.acquire().await;
        let (stream, peer_addr) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        let snapshot = ctx.snapshot();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(stream, peer_addr, snapshot, router).await {
                tracing::debug!(error = %e, ip = %peer_addr.ip(), "mTLS conn ended");
            }
            drop(permit);
        });
    }
}

/// Classify a TLS accept failure into an operator-actionable log line. These fire for
/// every broken agent, so they must say WHY and what to do — a silent (debug-level)
/// handshake failure looks like "the agent just doesn't work" from the operator's seat.
pub(crate) fn log_handshake_failure(err: &std::io::Error, ip: std::net::IpAddr) {
    let msg = err.to_string();
    if msg.contains("sent no certificates") || msg.contains("NoCertificatesPresented") {
        tracing::warn!(
            %ip,
            "mTLS handshake failed: the client presented NO certificate. Its TLS stack is \
             not sending the client cert (misconfigured identity, or cert material loaded \
             after the TLS session was created) — this is an agent-side bug, not a \
             revoked/expired certificate."
        );
    } else if msg.contains("UnknownIssuer") {
        tracing::warn!(
            %ip,
            "mTLS handshake failed: client certificate is not signed by any known tenant \
             CA (stale enrollment, deleted tenant, or rotated CA) — re-enroll the host."
        );
    } else if msg.contains("Expired") || msg.contains("NotValidYet") {
        tracing::warn!(
            %ip,
            error = %msg,
            "mTLS handshake failed: client certificate is outside its validity window — \
             re-enroll the host (it missed its renewal window)."
        );
    } else if msg.contains("BadSignature") || msg.contains("invalid peer certificate") {
        tracing::warn!(
            %ip,
            error = %msg,
            "mTLS handshake failed: client certificate rejected"
        );
    } else {
        // Plain TCP probes, port scanners, TLS-version mismatches, agents pinning a
        // stale server cert. Common enough to keep at info, but still visible.
        tracing::info!(%ip, error = %msg, "mTLS handshake failed");
    }
}

async fn handle_conn(
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    state: Arc<MtlsState>,
    router: Router,
) -> Result<()> {
    let acceptor = TlsAcceptor::from(state.tls_config.clone());
    let tls = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            log_handshake_failure(&e, peer_addr.ip());
            return Ok(());
        }
        Err(_) => {
            tracing::info!(ip = %peer_addr.ip(), "mTLS handshake timed out");
            return Ok(());
        }
    };
    serve_tls_conn(tls, peer_addr, state, router).await
}

/// Everything after a successful agent handshake: authenticate the peer from its client
/// certificate, then run the agent router over the connection.
///
/// Split out from `handle_conn` so the shared-port mux (`crate::mux`), which performs the
/// handshake itself in order to pick a `ServerConfig` from the ClientHello, can reuse the
/// identical authentication path. There must be exactly one implementation of this — it is
/// the boundary that turns a TLS peer into a `PeerHostContext`.
pub(crate) async fn serve_tls_conn(
    tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    peer_addr: SocketAddr,
    state: Arc<MtlsState>,
    router: Router,
) -> Result<()> {
    let peer_chain = tls
        .get_ref()
        .1
        .peer_certificates()
        .ok_or_else(|| anyhow!("no peer certs"))?
        .to_vec();
    if peer_chain.is_empty() {
        return Err(anyhow!("empty peer chain"));
    }
    let leaf_der = peer_chain[0].clone();

    let leaf = match parse_leaf(&leaf_der, &state.tenant_by_issuer_der) {
        Ok(l) => l,
        Err(e) => {
            // The chain verified against a tenant CA but the leaf's identity claims are
            // inconsistent (missing SPIFFE SAN, tenant mismatch, unknown issuer DN).
            tracing::warn!(ip = %peer_addr.ip(), error = %e, "mTLS client rejected after handshake");
            return Ok(());
        }
    };
    tracing::debug!(
        host_id = %leaf.host_id,
        tenant_id = leaf.tenant_id,
        tenant_slug = %leaf.tenant_slug,
        serial = %leaf.serial_hex,
        "mTLS peer authenticated"
    );

    let io = TokioIo::new(tls);
    let leaf_for_svc = leaf.clone();
    let svc_fn = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
        let leaf = leaf_for_svc.clone();
        let mut svc = router.clone().into_service::<Incoming>();
        async move {
            req.extensions_mut().insert(leaf);
            svc.call(req).await
        }
    });

    http_builder()
        .serve_connection(io, svc_fn)
        .await
        .map_err(|e| anyhow!("http: {e}"))?;
    Ok(())
}

fn parse_leaf(
    der: &CertificateDer<'_>,
    tenant_by_issuer_der: &HashMap<Vec<u8>, (i64, String)>,
) -> Result<PeerHostContext> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(der.as_ref())
        .map_err(|e| anyhow!("parse leaf: {e}"))?;

    // The leaf's Issuer field — if we got here, rustls already verified the chain against
    // our trust store, so this issuer is authentic. Matched on its raw DER: an exact
    // lookup on the bytes the certificate carries, rather than a scan comparing printed
    // forms that two tenants could share.
    let issuer_der = parsed.tbs_certificate.issuer.as_raw();
    let (tenant_id, tenant_slug) =
        tenant_by_issuer_der
            .get(issuer_der)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "issuer not in tenant map: {}",
                    parsed.tbs_certificate.issuer
                )
            })?;

    // Now read the host_id and the SAN-encoded slug. Cross-check the slug.
    let mut san_slug: Option<String> = None;
    let mut san_host_id: Option<String> = None;
    if let Ok(Some(san_ext)) = parsed.tbs_certificate.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            if let x509_parser::extensions::GeneralName::URI(uri) = name {
                // Expected: spiffe://nsclient-fleet/<slug>/<host_id>
                if let Some(rest) = uri.strip_prefix("spiffe://nsclient-fleet/") {
                    let mut parts = rest.splitn(2, '/');
                    if let (Some(s), Some(h)) = (parts.next(), parts.next()) {
                        san_slug = Some(s.to_string());
                        san_host_id = Some(h.to_string());
                    }
                }
            }
        }
    }
    let san_slug = san_slug.ok_or_else(|| anyhow!("leaf missing SPIFFE SAN URI"))?;
    let host_id = san_host_id.ok_or_else(|| anyhow!("leaf missing host id in SAN"))?;
    if san_slug != tenant_slug {
        return Err(anyhow!(
            "tenant mismatch: SAN={san_slug}, issuer-resolved={tenant_slug}"
        ));
    }

    // Use the raw DER serial bytes and zero-pad each. Matches the encoding produced by
    // sign.rs at issuance — `to_str_radix(16)` would strip leading zero nibbles and break
    // the comparison against the stored cert row.
    let serial_hex: String = parsed
        .tbs_certificate
        .raw_serial()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();

    Ok(PeerHostContext {
        tenant_id,
        tenant_slug,
        host_id,
        serial_hex,
    })
}

/// The raw DER of a CA certificate's subject, which is exactly the bytes a leaf issued by
/// it carries in its issuer field.
///
/// This replaces canonicalising the printed DN. Printed forms differ between libraries in
/// RDN ordering and casing, which is why the old code lowercased and stripped whitespace —
/// and stripping whitespace is what let `ac me` and `acme` become the same key.
fn ca_subject_der(cert_der: &[u8]) -> Result<Vec<u8>> {
    let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow!("parse ca: {e}"))?;
    Ok(parsed.tbs_certificate.subject.as_raw().to_vec())
}

/// Load the mTLS server identity from `dir`, generating and persisting it on first run.
///
/// Agents pin this cert (the enroll/renew responses hand it out as `mtls_server_cert_pem`),
/// so it MUST be stable across restarts — a regenerated cert strands every enrolled agent
/// with no self-service recovery, because renewal itself requires a working mTLS session.
/// Regeneration therefore happens only when the stored cert is unusable: it doesn't cover
/// `host` (MTLS_HOST changed) or it is within 30 days of expiry. Both cases invalidate
/// pinned copies, so they log a loud warning.
pub fn load_or_generate_server(dir: &std::path::Path, host: &str) -> Result<(String, String)> {
    let cert_path = dir.join("mtls-server.crt");
    let key_path = dir.join("mtls-server.key");

    if cert_path.exists() && key_path.exists() {
        let cert_pem = std::fs::read_to_string(&cert_path)
            .with_context(|| format!("read {}", cert_path.display()))?;
        let key_pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("read {}", key_path.display()))?;
        match stored_cert_usable(&cert_pem, host) {
            Ok(()) => {
                tracing::info!(path = %cert_path.display(), "reusing persisted mTLS server cert");
                return Ok((cert_pem, key_pem));
            }
            Err(reason) => {
                tracing::warn!(
                    %reason,
                    path = %cert_path.display(),
                    "persisted mTLS server cert unusable — regenerating. Agents enrolled \
                     against the old cert cannot connect and must be re-enrolled."
                );
            }
        }
    }

    let (cert_pem, key_pem) = generate_self_signed_server(host)?;
    std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    std::fs::write(&cert_path, &cert_pem)
        .with_context(|| format!("write {}", cert_path.display()))?;
    write_key_restricted(&key_path, &key_pem)?;
    tracing::info!(path = %cert_path.display(), %host, "generated and persisted mTLS server cert");
    Ok((cert_pem, key_pem))
}

/// A stored cert is reusable iff it covers `host` in its SAN (DNS or IP form) and has at
/// least 30 days of validity left.
fn stored_cert_usable(cert_pem: &str, host: &str) -> std::result::Result<(), String> {
    let der = parse_first_cert_pem(cert_pem).map_err(|e| format!("unparseable pem: {e}"))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| format!("unparseable der: {e}"))?;

    let wanted_ip: Option<std::net::IpAddr> = host.parse().ok();
    let covered = cert
        .tbs_certificate
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value.general_names.iter().any(|n| match n {
                x509_parser::extensions::GeneralName::DNSName(d) => d.eq_ignore_ascii_case(host),
                x509_parser::extensions::GeneralName::IPAddress(octets) => match wanted_ip {
                    Some(std::net::IpAddr::V4(v4)) => octets == &v4.octets(),
                    Some(std::net::IpAddr::V6(v6)) => octets == &v6.octets(),
                    None => false,
                },
                _ => false,
            })
        })
        .unwrap_or(false);
    if !covered {
        return Err(format!(
            "SAN does not cover host {host} (MTLS_HOST changed?)"
        ));
    }

    cert_valid_for_at_least(cert_pem, 30 * 86_400)
}

/// Write a private key, readable only by its owner where the platform can say so.
///
/// `#[cfg(unix)]` on the permission half, not on the whole function: on Windows the key
/// inherits the directory's ACL, which is why the deployment guide tells operators to put
/// the data directory somewhere only the service account can read.
pub(crate) fn write_key_restricted(path: &std::path::Path, key_pem: &str) -> Result<()> {
    std::fs::write(path, key_pem).with_context(|| format!("write {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

/// Generate a self-signed server cert for the mTLS port. Callers should prefer
/// `load_or_generate_server`, which persists the result — agents pin this cert, so an
/// ephemeral one strands the fleet on every restart. Direct generation is for tests.
pub fn generate_self_signed_server(host: &str) -> Result<(String, String)> {
    generate_self_signed(std::slice::from_ref(&host.to_string()))
}

/// Generate a self-signed server certificate covering every name in `hosts`.
///
/// `hosts` entries that parse as IP addresses become IP SANs and the rest become DNS SANs —
/// rcgen decides that per entry, which is what lets one call cover `fleet.internal`,
/// `localhost` and `127.0.0.1` together. The first entry is also the Common Name, so put the
/// name operators actually type first.
///
/// Ten years of validity: nothing trusts this by its issuer, so a short life buys no
/// revocation story and only guarantees an outage on a box nobody has logged into for a
/// year. The agent certificate has the same reasoning and the same lifetime.
pub fn generate_self_signed(hosts: &[String]) -> Result<(String, String)> {
    let Some(primary) = hosts.first() else {
        anyhow::bail!("a self-signed certificate needs at least one host name");
    };
    let mut params = rcgen::CertificateParams::new(hosts.to_vec())?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, primary.clone());
    params.is_ca = rcgen::IsCa::ExplicitNoCa;
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(3650);

    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&kp)?;
    Ok((cert.pem(), kp.serialize_pem()))
}

/// `Ok(())` when `cert_pem` parses and has at least `min_remaining_secs` of validity left.
///
/// Shared with the web-certificate path, which has the same "is this still worth reusing?"
/// question but none of the SAN pinning constraints — so the expiry half lives here and each
/// caller decides what else makes a stored certificate unusable.
pub(crate) fn cert_valid_for_at_least(
    cert_pem: &str,
    min_remaining_secs: i64,
) -> std::result::Result<(), String> {
    let der = parse_first_cert_pem(cert_pem).map_err(|e| format!("unparseable pem: {e}"))?;
    let (_, cert) = x509_parser::certificate::X509Certificate::from_der(&der)
        .map_err(|e| format!("unparseable der: {e}"))?;
    if cert.validity().not_after.timestamp() < fleet_core::time::now_unix() + min_remaining_secs {
        return Err(format!(
            "expires within {} days",
            min_remaining_secs / 86_400
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn persisted_cert_is_reused_across_restarts() {
        let dir = TempDir::new().unwrap();
        let (cert1, key1) = load_or_generate_server(dir.path(), "localhost").unwrap();
        let (cert2, key2) = load_or_generate_server(dir.path(), "localhost").unwrap();
        assert_eq!(cert1, cert2, "second startup must reuse the same cert");
        assert_eq!(key1, key2);
        assert!(dir.path().join("mtls-server.crt").exists());
        assert!(dir.path().join("mtls-server.key").exists());
    }

    #[test]
    fn host_change_regenerates() {
        let dir = TempDir::new().unwrap();
        let (cert1, _) = load_or_generate_server(dir.path(), "localhost").unwrap();
        let (cert2, _) = load_or_generate_server(dir.path(), "control.example.com").unwrap();
        assert_ne!(cert1, cert2, "SAN mismatch must trigger regeneration");
        // And the new cert is stable from then on.
        let (cert3, _) = load_or_generate_server(dir.path(), "control.example.com").unwrap();
        assert_eq!(cert2, cert3);
    }

    #[test]
    fn ip_hosts_are_covered_and_reused() {
        let dir = TempDir::new().unwrap();
        let (cert1, _) = load_or_generate_server(dir.path(), "127.0.0.1").unwrap();
        let (cert2, _) = load_or_generate_server(dir.path(), "127.0.0.1").unwrap();
        assert_eq!(cert1, cert2, "IP SAN must be recognized on reload");
    }

    /// The contract that authenticates every agent: the serial recorded at issuance must
    /// equal the serial parsed back out of the certificate on the wire. `parse_leaf` uses
    /// `raw_serial()` (DER content octets, minimally encoded); `sign_client_cert` records
    /// the raw 16 bytes it asked for. If those two encodings ever disagree, `is_active`
    /// rejects the host with "cert revoked or unknown" and it cannot renew its way out.
    #[test]
    fn issued_serial_matches_the_one_parsed_off_the_wire() {
        let secrets = fleet_enrollment::generate_tenant_ca("acme").unwrap();
        let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut csr_params = rcgen::CertificateParams::default();
        csr_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client");
        let csr_pem = csr_params.serialize_request(&key).unwrap().pem().unwrap();

        // Sampled, because the failure was probabilistic in the serial's first byte.
        for _ in 0..64 {
            let issued = fleet_enrollment::sign_client_cert(
                &csr_pem,
                &secrets.ca.cert_pem,
                &secrets.ca.key_pem,
                "acme",
                "host-xyz",
                90,
            )
            .unwrap();

            let der = parse_first_cert_pem(&issued.cert_pem).unwrap();
            let (_, parsed) = x509_parser::certificate::X509Certificate::from_der(&der).unwrap();
            let on_the_wire: String = parsed
                .tbs_certificate
                .raw_serial()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();

            assert_eq!(
                on_the_wire, issued.serial_hex,
                "serial encoding must round-trip exactly"
            );
        }
    }

    /// One certificate has to cover the name an operator types, loopback, and often a bare
    /// IP — that is the whole point of TLS_HOSTS, and rcgen has to be picking the SAN type
    /// per entry for it to work.
    #[test]
    fn a_generated_web_cert_covers_every_host_it_was_given() {
        let hosts: Vec<String> = ["fleet.internal", "localhost", "127.0.0.1"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let (cert_pem, key_pem) = generate_self_signed(&hosts).unwrap();
        assert!(key_pem.contains("PRIVATE KEY"));
        for host in &hosts {
            assert_eq!(
                stored_cert_usable(&cert_pem, host),
                Ok(()),
                "SAN should cover {host}"
            );
        }
        assert!(
            stored_cert_usable(&cert_pem, "elsewhere.internal").is_err(),
            "a name that was never asked for must not match"
        );
    }

    #[test]
    fn generating_without_a_host_is_an_error() {
        assert!(generate_self_signed(&[]).is_err());
    }

    /// The shared expiry check backs both "may I reuse the agent cert?" and "may I reuse the
    /// web cert?", so it has to answer for a freshly minted certificate and for one whose
    /// remaining life is shorter than the window asked about.
    #[test]
    fn expiry_window_is_measured_against_remaining_life() {
        let (cert_pem, _) = generate_self_signed_server("localhost").unwrap();
        assert_eq!(cert_valid_for_at_least(&cert_pem, 30 * 86_400), Ok(()));
        // Generated certs live ten years; ask for eleven and it is too short.
        assert!(cert_valid_for_at_least(&cert_pem, 11 * 365 * 86_400).is_err());
        assert!(cert_valid_for_at_least("not a pem", 1).is_err());
    }

    #[test]
    fn hostname_check_is_case_insensitive() {
        let (cert, _) = generate_self_signed_server("Control.Example.Com").unwrap();
        assert!(stored_cert_usable(&cert, "control.example.com").is_ok());
    }
}
