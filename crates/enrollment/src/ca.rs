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

    /// A bundle-signing key pair as stored by the build before the crypto-crate upgrade (see
    /// `testdata/kat`). The server loads the private half to sign every bundle descriptor
    /// and checks old signatures against the public half at startup; agents pin the public
    /// half. Ed25519 is deterministic, so the signature has to come out byte for byte.
    #[test]
    fn stored_bundle_signing_keys_still_load_and_sign_the_same() {
        use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
        use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};

        const MESSAGE: &[u8] = b"nsclient-fleet kat descriptor";
        const SIGNATURE: &str = "a8e5bd4b796fa62a53647b3f6c360746801e98cce7290454fc28d7f1fb4625d1\
                                 0c0e39df99d5ee4151d7df8bde46e69d6b47f7db391e1b008a3e7bb080406400";

        let key =
            SigningKey::from_pkcs8_pem(include_str!("../testdata/kat/bundle-signing.key")).unwrap();
        let sig = key.sign(MESSAGE).to_bytes();
        assert_eq!(fleet_core::digest::hex(&sig), SIGNATURE);

        let public =
            VerifyingKey::from_public_key_pem(include_str!("../testdata/kat/bundle-signing.pub"))
                .unwrap();
        assert_eq!(public, key.verifying_key());
        assert!(public.verify(MESSAGE, &Signature::from_bytes(&sig)).is_ok());
    }
}
