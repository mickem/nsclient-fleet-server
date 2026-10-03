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
    /// Bundle-encryption keys (base64), newest first — a real agent reads these from local
    /// config, provisioned out-of-band; they never come from the server. Multiple entries
    /// exist only mid-rotation.
    pub bundle_encryption_keys: Vec<String>,
    /// When set, refuse any bundle that is not an authenticated NSEB1 envelope — the
    /// "cloud is untrusted" posture: bundle content must be produced by a key holder.
    pub require_encrypted_bundles: bool,
    /// Report `host_override_last: true` on every state report, as an agent that merges the
    /// host override after the bundles does. Off by default: the older wire shape.
    pub host_override_last: bool,
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
        bundle_encryption_keys: Vec::new(),
        require_encrypted_bundles: false,
        host_override_last: false,
    })
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredState {
    /// Part of the descriptor a bundle's signature covers. Defaulted so a response from a
    /// server predating the field still deserializes — signature verification then fails,
    /// which is the correct answer for a server that cannot say which tenant it is.
    #[serde(default)]
    pub tenant_id: i64,
    pub state_hash: String,
    pub next_poll_in_seconds: u32,
    pub merged_config_json: serde_json::Value,
    #[serde(default)]
    pub bundles: Vec<serde_json::Value>,
}

impl DesiredState {
    /// The signed descriptor for one entry of `bundles`, as the server advertised it.
    ///
    /// Reading the fields out of the response rather than reconstructing them is the point:
    /// the agent verifies the server's own claim about what this bundle *is*, so a claim
    /// that does not match what was signed fails rather than being quietly accepted.
    pub fn descriptor<'a>(
        &'a self,
        bundle: &'a serde_json::Value,
    ) -> Result<fleet_core::bundlesig::BundleDescriptor<'a>> {
        let field = |k: &str| -> Result<&'a str> {
            bundle[k]
                .as_str()
                .ok_or_else(|| anyhow!("bundle entry is missing a string `{k}`"))
        };
        Ok(fleet_core::bundlesig::BundleDescriptor {
            tenant_id: self.tenant_id,
            bundle_id: field("id")?,
            name: field("name")?,
            version: field("version")?,
            format: field("format")?,
            sha256_hex: field("sha256")?,
        })
    }
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
    /// Omitted when `None`: an agent that merges the host override first.
    #[serde(skip_serializing_if = "Option::is_none")]
    host_override_last: Option<bool>,
    /// Omitted when `None`: an agent without facts support.
    #[serde(skip_serializing_if = "Option::is_none")]
    facts_hash: Option<&'a str>,
}

/// The `X-Facts-Hash` answer: `None` when the server sent no header (it does not do facts),
/// otherwise the header's value — `none` or a hash.
fn facts_header(res: &reqwest::Response) -> Option<String> {
    res.headers()
        .get("x-facts-hash")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// A `/agent/v1/facts` body the way the agent builds it: the document spliced in verbatim
/// and hashed as those exact bytes, members in sorted order.
pub fn facts_upload_body(facts_json: &str, collected_at: &str) -> String {
    format!(
        "{{\"collected_at\":{},\"facts\":{facts_json},\"facts_hash\":\"{}\"}}",
        serde_json::to_string(collected_at).expect("string serializes"),
        fleet_core::facts::sha256_hex(facts_json.as_bytes())
    )
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
        Ok(self.poll(current_hash, None).await?.0)
    }

    /// Poll the way a facts-aware agent does: carrying the hash of its facts document, and
    /// reading back the hash the server holds. Returns the desired state (`None` on 304) and
    /// the `X-Facts-Hash` answer.
    pub async fn poll_with_facts(
        &self,
        current_hash: Option<&str>,
        facts_hash: &str,
    ) -> Result<(Option<DesiredState>, Option<String>)> {
        self.poll(current_hash, Some(facts_hash)).await
    }

    /// The one desired-state request: `facts_hash` omitted is an agent without facts.
    async fn poll(
        &self,
        current_hash: Option<&str>,
        facts_hash: Option<&str>,
    ) -> Result<(Option<DesiredState>, Option<String>)> {
        let client = self.mtls_client()?;
        let mut url = format!(
            "{}/agent/v1/desired-state",
            self.mtls_url.trim_end_matches('/')
        );
        let query: Vec<String> = [("current_hash", current_hash), ("facts_hash", facts_hash)]
            .into_iter()
            .filter_map(|(k, v)| v.map(|v| format!("{k}={v}")))
            .collect();
        if !query.is_empty() {
            url.push('?');
            url.push_str(&query.join("&"));
        }
        let res = client.get(&url).send().await?;
        let held = facts_header(&res);
        match res.status().as_u16() {
            200 => Ok((Some(res.json::<DesiredState>().await?), held)),
            304 => Ok((None, held)),
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

    /// A state report carrying a facts hash. Returns the `X-Facts-Hash` answer.
    pub async fn report_state_with_facts(
        &self,
        applied_state_hash: Option<&str>,
        reported_tags: BTreeMap<String, String>,
        facts_hash: &str,
    ) -> Result<Option<String>> {
        self.send_state_report(
            applied_state_hash,
            reported_tags,
            Some(false),
            Some(facts_hash),
        )
        .await
    }

    /// POST a raw `/agent/v1/facts` body. Returns the status and the `X-Facts-Hash` answer;
    /// a refusal is a status, not an error, so tests can assert on it.
    pub async fn upload_facts(&self, body: String) -> Result<(u16, Option<String>)> {
        let client = self.mtls_client()?;
        let url = format!("{}/agent/v1/facts", self.mtls_url.trim_end_matches('/'));
        let res = client
            .post(&url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        Ok((res.status().as_u16(), facts_header(&res)))
    }

    /// Report state the way an agent predating `local_config_present` does: without the
    /// field at all. Kept as the default so the tests that do not care about it keep
    /// exercising the older wire shape.
    pub async fn report_state(
        &self,
        applied_state_hash: Option<&str>,
        reported_tags: BTreeMap<String, String>,
    ) -> Result<()> {
        self.send_state_report(applied_state_hash, reported_tags, None, None)
            .await
            .map(drop)
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
            None,
        )
        .await
        .map(drop)
    }

    /// The one state-report request. Returns the `X-Facts-Hash` answer.
    async fn send_state_report(
        &self,
        applied_state_hash: Option<&str>,
        reported_tags: BTreeMap<String, String>,
        local_config_present: Option<bool>,
        facts_hash: Option<&str>,
    ) -> Result<Option<String>> {
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
            host_override_last: self.host_override_last.then_some(true),
            facts_hash,
        };
        let res = client.post(&url).json(&body).send().await?;
        if !res.status().is_success() {
            let status = res.status();
            let text = res.text().await.unwrap_or_default();
            return Err(anyhow!("state-report failed: {status} — {text}"));
        }
        Ok(facts_header(&res))
    }

    /// Download a bundle by id and verify integrity (sha256) + authenticity.
    ///
    /// The signature is Ed25519 over the bundle's *descriptor* — tenant, id, name, version,
    /// format and digest — not over the digest alone, so it says which bundle these bytes
    /// are and not merely that the server once saw them. See `fleet_core::bundlesig`.
    #[allow(clippy::too_many_arguments)]
    pub async fn fetch_bundle_verified(
        &self,
        descriptor: fleet_core::bundlesig::BundleDescriptor<'_>,
        signature_b64: &str,
    ) -> Result<Vec<u8>> {
        let bundle_id = descriptor.bundle_id;
        let expected_sha256_hex = descriptor.sha256_hex;
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

        // 2. signature over the descriptor the server advertised for this bundle. The
        //    digest is one field of it, so step 1 having passed means the signature now
        //    covers these exact bytes *under this identity*.
        let sig_bytes = STANDARD
            .decode(signature_b64)
            .map_err(|e| anyhow!("signature base64: {e}"))?;
        let sig = Signature::from_slice(&sig_bytes).map_err(|e| anyhow!("signature parse: {e}"))?;
        let vk = VerifyingKey::from_public_key_pem(&self.bundle_signing_pub_pem)
            .map_err(|e| anyhow!("verifying key parse: {e}"))?;
        vk.verify(&descriptor.to_signing_bytes(), &sig)
            .map_err(|e| anyhow!("signature verify failed: {e}"))?;

        Ok(bytes)
    }

    /// Second half of the apply path: turn verified bundle bytes into the usable zip.
    ///
    /// Detection is by the NSEB1 magic in the bytes, not by any server-declared format —
    /// the magic is inside the blob the signature covered, so a lying server cannot make
    /// an encrypted bundle look plain or vice versa without failing verification anyway.
    /// `name`/`version` must be the identity the server advertised for this bundle; they
    /// are bound into the AEAD, so decryption doubles as a substitution check.
    pub fn open_bundle(&self, name: &str, version: &str, bytes: Vec<u8>) -> Result<Vec<u8>> {
        use fleet_core::encbundle::{self, BundleKey, EncBundleError};

        if !encbundle::is_encrypted(&bytes) {
            if self.require_encrypted_bundles {
                return Err(anyhow!(
                    "bundle {name}@{version} is not encrypted but this agent requires encrypted bundles"
                ));
            }
            return Ok(bytes);
        }

        let header = encbundle::parse_header(&bytes).map_err(|e| anyhow!("bad envelope: {e}"))?;
        for key_b64 in &self.bundle_encryption_keys {
            let key = BundleKey::from_b64(key_b64).map_err(|e| anyhow!("bad local key: {e}"))?;
            match key.decrypt(name, version, &bytes) {
                Ok(plain) => return Ok(plain),
                Err(EncBundleError::WrongKey) => continue,
                Err(e) => return Err(anyhow!("decrypt {name}@{version}: {e}")),
            }
        }
        Err(anyhow!(
            "no local key matches bundle {name}@{version} (fingerprint {})",
            header.fingerprint_hex()
        ))
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
    use rustls::pki_types::pem::PemObject;
    let out = rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes())
        .map(|c| c.map(|c| c.as_ref().to_vec()))
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("pem parse: {e:?}"))?;
    if out.is_empty() {
        Err(anyhow!("no certificates in PEM"))
    } else {
        Ok(out)
    }
}

fn parse_pkcs8_key(pem: &str) -> Result<Vec<u8>> {
    use rustls::pki_types::pem::PemObject;
    rustls::pki_types::PrivatePkcs8KeyDer::from_pem_slice(pem.as_bytes())
        .map(|k| k.secret_pkcs8_der().to_vec())
        .map_err(|e| anyhow!("no pkcs8 private key in PEM: {e:?}"))
}
