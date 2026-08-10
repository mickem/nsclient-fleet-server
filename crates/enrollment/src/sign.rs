use rcgen::{
    CertificateParams, CertificateSigningRequestParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, SanType,
};
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error)]
pub enum SignError {
    #[error("malformed CSR: {0}")]
    BadCsr(String),
    #[error("unsupported public key algorithm")]
    UnsupportedKey,
    #[error("CA load failed: {0}")]
    CaLoad(String),
    #[error("rcgen: {0}")]
    Rcgen(#[from] rcgen::Error),
}

pub struct IssuedCert {
    pub cert_pem: String,
    pub serial_hex: String,
    pub fingerprint_sha256_hex: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
}

pub fn sign_client_cert(
    csr_pem: &str,
    ca_cert_pem: &str,
    ca_key_pem: &str,
    tenant_slug: &str,
    host_id: &str,
    lifetime_days: i64,
) -> Result<IssuedCert, SignError> {
    let csr = CertificateSigningRequestParams::from_pem(csr_pem)
        .map_err(|e| SignError::BadCsr(e.to_string()))?;

    // We trust ONLY the public key from the CSR. Build the cert ourselves so the client
    // cannot influence Subject, SANs, EKU, or any extension.
    let public_key = csr.public_key;

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, host_id);
    dn.push(DnType::OrganizationName, "NSClient Fleet");
    params.distinguished_name = dn;
    params.subject_alt_names = vec![SanType::URI(
        format!("spiffe://nsclient-fleet/{tenant_slug}/{host_id}")
            .try_into()
            .expect("spiffe URI is ASCII"),
    )];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyAgreement,
    ];
    params.is_ca = rcgen::IsCa::ExplicitNoCa;

    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::minutes(5);
    params.not_after = now + time::Duration::days(lifetime_days);

    let serial_bytes = random_serial();
    params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial_bytes));

    let ca_key = KeyPair::from_pem(ca_key_pem).map_err(|e| SignError::CaLoad(e.to_string()))?;
    let ca_params = CertificateParams::from_ca_cert_pem(ca_cert_pem)
        .map_err(|e| SignError::CaLoad(e.to_string()))?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let not_before_unix = params.not_before.unix_timestamp();
    let not_after_unix = params.not_after.unix_timestamp();
    let cert = params.signed_by(&public_key, &ca_cert, &ca_key)?;

    let cert_pem = cert.pem();
    let der = cert.der();
    let fingerprint = Sha256::digest(der.as_ref());

    Ok(IssuedCert {
        cert_pem,
        serial_hex: hex(&serial_bytes),
        fingerprint_sha256_hex: hex(&fingerprint),
        not_before_unix,
        not_after_unix,
    })
}

/// A 16-byte certificate serial that survives DER round-tripping byte-for-byte.
///
/// Two constraints, both load-bearing:
/// - **Top bit clear** — a DER INTEGER is signed, so a leading byte ≥ 0x80 would encode as
///   a negative serial (or force an extra padding byte).
/// - **First byte non-zero** — DER INTEGERs are *minimally* encoded, so a leading 0x00 is
///   stripped on the wire. `serial_hex` below is the hex of these bytes, while the server
///   authenticates a client by hex-encoding the serial it parses back out of the
///   certificate (`mtls::parse_leaf`). If the two encodings can differ, that comparison
///   fails and the host is rejected as "cert revoked or unknown" forever — it cannot even
///   renew, because renewal is itself an mTLS call.
///
/// Without the non-zero constraint this hit 1 in 128 issued certificates.
fn random_serial() -> [u8; 16] {
    let mut bytes = [0u8; 16];
    rand::Rng::fill(&mut rand::thread_rng(), &mut bytes);
    bytes[0] = (bytes[0] & 0x7f) | 0x01;
    bytes
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ca::generate_tenant_ca;

    #[test]
    fn sign_round_trip() {
        let s = generate_tenant_ca("acme").unwrap();

        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut csr_params = CertificateParams::default();
        csr_params
            .distinguished_name
            .push(DnType::CommonName, "ignored-by-server");
        let csr_pem = csr_params.serialize_request(&key).unwrap().pem().unwrap();

        let issued = sign_client_cert(
            &csr_pem,
            &s.ca.cert_pem,
            &s.ca.key_pem,
            "acme",
            "host-xyz",
            90,
        )
        .unwrap();
        assert!(issued.cert_pem.contains("BEGIN CERTIFICATE"));
        assert_eq!(issued.serial_hex.len(), 32);
        assert_eq!(issued.fingerprint_sha256_hex.len(), 64);
        assert!(issued.not_after_unix > issued.not_before_unix);
    }

    /// Regression: a serial whose first byte is zero is stripped by DER's minimal-integer
    /// encoding, so the hex the server parses back off the wire no longer matches the hex
    /// stored at issuance and the host is permanently rejected. This used to happen to
    /// 1 in 128 certificates. Cheap enough to sample heavily, so make it certain.
    #[test]
    fn serials_survive_der_minimal_encoding() {
        for _ in 0..100_000 {
            let s = random_serial();
            assert_ne!(
                s[0], 0x00,
                "a leading zero byte is dropped by DER and breaks serial comparison"
            );
            assert!(
                s[0] < 0x80,
                "the top bit must stay clear or the INTEGER encodes as negative"
            );
        }
    }
}
