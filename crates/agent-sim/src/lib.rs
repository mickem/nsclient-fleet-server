use anyhow::{anyhow, Context, Result};
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct EnrollResponse {
    pub cert_pem: String,
    pub ca_pem: String,
    pub bundle_signing_pub_pem: String,
    pub server_url: String,
    pub mtls_url: String,
    pub mtls_server_cert_pem: String,
}

#[derive(Debug, Clone, Serialize)]
struct EnrollRequest<'a> {
    bootstrap_token: &'a str,
    csr_pem: String,
    hostname: Option<&'a str>,
    os: Option<&'a str>,
}

pub struct EnrolledAgent {
    pub key_pem: String,
    pub cert_pem: String,
    pub ca_pem: String,
    pub bundle_signing_pub_pem: String,
    pub mtls_url: String,
    pub mtls_server_cert_pem: String,
}

/// Generate an Ed25519 keypair, build a CSR, post it to /enroll/v1, return the issued
/// material plus everything the agent needs to reach the mTLS endpoint.
pub async fn enroll(
    server_url: &str,
    bootstrap_token: &str,
    hostname: Option<&str>,
    os: Option<&str>,
) -> Result<EnrolledAgent> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let keypair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let mut csr_params = CertificateParams::default();
    csr_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "client");
    let csr_pem = csr_params
        .serialize_request(&keypair)?
        .pem()
        .context("csr to pem")?;

    let body = EnrollRequest {
        bootstrap_token,
        csr_pem,
        hostname,
        os,
    };

    let url = format!("{}/enroll/v1", server_url.trim_end_matches('/'));
    let res = reqwest::Client::new().post(&url).json(&body).send().await?;
    if !res.status().is_success() {
        let status = res.status();
        let text = res.text().await.unwrap_or_default();
        return Err(anyhow!("enroll failed: {status} — {text}"));
    }
    let parsed: EnrollResponse = res.json().await?;

    Ok(EnrolledAgent {
        key_pem: keypair.serialize_pem(),
        cert_pem: parsed.cert_pem,
        ca_pem: parsed.ca_pem,
        bundle_signing_pub_pem: parsed.bundle_signing_pub_pem,
        mtls_url: parsed.mtls_url,
        mtls_server_cert_pem: parsed.mtls_server_cert_pem,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredState {
    pub state_hash: String,
    pub next_poll_in_seconds: u32,
    pub merged_config_json: serde_json::Value,
    #[serde(default)]
    pub bundles: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct StateReportBody<'a> {
    applied_state_hash: Option<&'a str>,
    bundles_installed: Vec<serde_json::Value>,
    errors: Vec<String>,
    reported_tags: BTreeMap<String, String>,
    /// Omitted entirely when `None`, which is what an agent older than the field looks like
    /// on the wire — the server has to keep telling that apart from an explicit `false`.
    #[serde(skip_serializing_if = "Option::is_none")]
    local_config_present: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RenewedMaterial {
    pub cert_pem: String,
    pub ca_pem: String,
    pub mtls_server_cert_pem: String,
    pub bundle_signing_pub_pem: String,
}

#[derive(Debug, Serialize)]
struct RenewBody {
    csr_pem: String,
}

impl EnrolledAgent {
    pub fn mtls_client(&self) -> Result<reqwest::Client> {
        let client_certs = parse_certs(&self.cert_pem)?;
        let client_key = parse_pkcs8_key(&self.key_pem)?;

        let mut roots = rustls::RootCertStore::empty();
        for cert in parse_certs(&self.mtls_server_cert_pem)? {
            roots.add(CertificateDer::from(cert))?;
        }

        let key_der: PrivateKeyDer<'static> = PrivatePkcs8KeyDer::from(client_key).into();
        let mut cfg = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                client_certs.into_iter().map(CertificateDer::from).collect(),
                key_der,
            )?;

        // Declare ourselves an agent in the ClientHello. This is what lets the server run
        // agent mTLS on the same :443 as the operator UI — see `fleet_server::mux`. Kept
        // first with http/1.1 behind it so a server on a dedicated mTLS port, which has no
        // reason to know about `nsclient-fleet/1`, still negotiates something.
        //
        // reqwest preserves alpn_protocols on a preconfigured rustls config (it only
        // rewrites them when it builds the config itself), so this survives to the wire.
        cfg.alpn_protocols = vec![fleet_proto::AGENT_ALPN.to_vec(), b"http/1.1".to_vec()];

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(cfg)
            .build()?;
        Ok(client)
    }

    pub async fn heartbeat(&self) -> Result<serde_json::Value> {
        let client = self.mtls_client()?;
        let url = format!("{}/agent/v1/heartbeat", self.mtls_url.trim_end_matches('/'));
        let res = client.get(&url).send().await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("heartbeat failed: {status} — {text}"));
        }
        Ok(res.json().await?)
    }

    /// Fetch desired state. Returns Ok(Some(state)) on 200, Ok(None) on 304 (matched the
    /// caller-provided current_hash), Err on anything else.
    pub async fn fetch_desired_state(
        &self,
        current_hash: Option<&str>,
    ) -> Result<Option<DesiredState>> {
        let client = self.mtls_client()?;
        let mut url = format!(
            "{}/agent/v1/desired-state",
            self.mtls_url.trim_end_matches('/')
        );
        if let Some(h) = current_hash {
            url.push_str(&format!("?current_hash={h}"));
        }
        let res = client.get(&url).send().await?;
        match res.status().as_u16() {
            200 => Ok(Some(res.json::<DesiredState>().await?)),
            304 => Ok(None),
            429 => Err(anyhow!(
                "rate limited (retry-after {})",
                res.headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("?")
            )),
            other => Err(anyhow!(
                "desired-state failed: {} — {}",
                other,
                res.text().await.unwrap_or_default()
            )),
        }
    }

    /// Report state the way an agent predating `local_config_present` does: without the
    /// field at all. Kept as the default so the tests that do not care about it keep
    /// exercising the older wire shape.
    pub async fn report_state(
        &self,
        applied_state_hash: Option<&str>,
        reported_tags: BTreeMap<String, String>,
    ) -> Result<()> {
        self.send_state_report(applied_state_hash, reported_tags, None)
            .await
    }

    /// Report state the way a current agent does: always carrying whether the host has
    /// local configuration outranking the fleet's, in both directions.
    pub async fn report_state_with_local_config(
        &self,
        applied_state_hash: Option<&str>,
        reported_tags: BTreeMap<String, String>,
        local_config_present: bool,
    ) -> Result<()> {
        self.send_state_report(
            applied_state_hash,
            reported_tags,
            Some(local_config_present),
        )
        .await
    }

    async fn send_state_report(
        &self,
        applied_state_hash: Option<&str>,
        reported_tags: BTreeMap<String, String>,
        local_config_present: Option<bool>,
    ) -> Result<()> {
        let client = self.mtls_client()?;
        let url = format!(
            "{}/agent/v1/state-report",
            self.mtls_url.trim_end_matches('/')
        );
        let body = StateReportBody {
            applied_state_hash,
            bundles_installed: vec![],
            errors: vec![],
            reported_tags,
            local_config_present,
        };
        let res = client.post(&url).json(&body).send().await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("state-report failed: {status} — {text}"));
        }
        Ok(())
    }

    /// Download a bundle by id and verify integrity (sha256) + signature (Ed25519 over the
    /// SHA-256 digest of the bytes, using the bundle-signing pubkey received at enrollment).
    pub async fn fetch_bundle(
        &self,
        bundle_id: &str,
        expected_sha256_hex: &str,
        signature_b64: &str,
    ) -> Result<Vec<u8>> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use ed25519_dalek::pkcs8::DecodePublicKey;
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        use sha2::{Digest, Sha256};

        let client = self.mtls_client()?;
        let url = format!(
            "{}/agent/v1/bundles/{}",
            self.mtls_url.trim_end_matches('/'),
            bundle_id
        );
        let res = client.get(&url).send().await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("fetch_bundle: {status} — {text}"));
        }
        let bytes = res.bytes().await?.to_vec();

        // 1. sha256
        let actual = Sha256::digest(&bytes);
        let actual_hex: String = actual.iter().map(|b| format!("{b:02x}")).collect();
        if actual_hex != expected_sha256_hex {
            return Err(anyhow!(
                "sha256 mismatch (expected {expected_sha256_hex}, got {actual_hex})"
            ));
        }

        // 2. signature over the sha256 digest
        let sig_bytes = STANDARD
            .decode(signature_b64)
            .map_err(|e| anyhow!("signature base64: {e}"))?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|e| anyhow!("signature parse: {e}"))?;
        let vk = VerifyingKey::from_public_key_pem(&self.bundle_signing_pub_pem)
            .map_err(|e| anyhow!("verifying key parse: {e}"))?;
        vk.verify(&actual, &sig)
            .map_err(|e| anyhow!("signature verify failed: {e}"))?;

        Ok(bytes)
    }

    /// Generate a fresh keypair, post a CSR to `/agent/v1/renew`, and atomically swap the
    /// active mTLS identity. Old serial stays valid until natural expiry server-side.
    pub async fn renew(&mut self) -> Result<()> {
        let client = self.mtls_client()?;
        let keypair = KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let mut csr_params = CertificateParams::default();
        csr_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client");
        let csr_pem = csr_params
            .serialize_request(&keypair)?
            .pem()
            .context("csr to pem")?;

        let url = format!("{}/agent/v1/renew", self.mtls_url.trim_end_matches('/'));
        let res = client
            .post(&url)
            .json(&RenewBody { csr_pem })
            .send()
            .await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("renew failed: {status} — {text}"));
        }
        let renewed: RenewedMaterial = res.json().await?;
        self.key_pem = keypair.serialize_pem();
        self.cert_pem = renewed.cert_pem;
        self.ca_pem = renewed.ca_pem;
        self.mtls_server_cert_pem = renewed.mtls_server_cert_pem;
        self.bundle_signing_pub_pem = renewed.bundle_signing_pub_pem;
        Ok(())
    }
}

fn parse_certs(pem: &str) -> Result<Vec<Vec<u8>>> {
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

fn parse_pkcs8_key(pem: &str) -> Result<Vec<u8>> {
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
