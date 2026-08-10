use anyhow::Result;
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, KeyUsagePurpose};

pub struct TenantCa {
    pub cert_pem: String,
    pub key_pem: String,
    pub subject_dn: String,
}

pub struct TenantSecrets {
    pub ca: TenantCa,
    pub bundle_signing_key_pem: String,
    pub bundle_signing_pub_pem: String,
}

/// Generate a fresh per-tenant CA (P-256 ECDSA) and bundle-signing key (Ed25519).
/// Caller is responsible for encrypting the private material with the master key before persisting.
pub fn generate_tenant_ca(slug: &str) -> Result<TenantSecrets> {
    let subject_dn = format!("CN=tenant-{slug}-ca,O=NSClient Fleet");

    let mut params = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, format!("tenant-{slug}-ca"));
    dn.push(DnType::OrganizationName, "NSClient Fleet");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::hours(1);
    params.not_after = now + time::Duration::days(3650); // 10y

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
    let cert = params.self_signed(&key_pair)?;

    let mut signing_csprng = OsRng;
    let bundle_key = SigningKey::generate(&mut signing_csprng);
    let bundle_key_pem = ed25519_pkcs8_pem(&bundle_key);
    let bundle_pub_pem = ed25519_spki_pem(&bundle_key);

    Ok(TenantSecrets {
        ca: TenantCa {
            cert_pem: cert.pem(),
            key_pem: key_pair.serialize_pem(),
            subject_dn,
        },
        bundle_signing_key_pem: bundle_key_pem,
        bundle_signing_pub_pem: bundle_pub_pem,
    })
}

fn ed25519_pkcs8_pem(key: &SigningKey) -> String {
    use ed25519_dalek::pkcs8::EncodePrivateKey;
    key.to_pkcs8_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("ed25519 pkcs8 encode")
        .to_string()
}

fn ed25519_spki_pem(key: &SigningKey) -> String {
    use ed25519_dalek::pkcs8::EncodePublicKey;
    let vk = key.verifying_key();
    vk.to_public_key_pem(ed25519_dalek::pkcs8::spki::der::pem::LineEnding::LF)
        .expect("ed25519 spki encode")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_pem_artifacts() {
        let s = generate_tenant_ca("acme").unwrap();
        assert!(s.ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(s.ca.key_pem.contains("PRIVATE KEY"));
        assert!(s.bundle_signing_key_pem.contains("PRIVATE KEY"));
        assert!(s.bundle_signing_pub_pem.contains("PUBLIC KEY"));
        assert_eq!(s.ca.subject_dn, "CN=tenant-acme-ca,O=NSClient Fleet");
    }
}
