//! At-rest encryption under `MASTER_KEY`.
//!
//! Every ciphertext is bound to what it is and whose it is, through the AEAD's associated
//! data. Without that binding the ciphertexts are interchangeable: anyone who can write to
//! the database — which is the access this encryption exists to blunt — could move tenant
//! A's encrypted host override onto a host in tenant B and have the server decrypt and
//! serve it, or swap two tenants' encrypted CA keys so one tenant's certificates come out
//! signed by the other's CA. Neither needs the key.
//!
//! The binding is a [`Purpose`], and it is a required argument rather than an optional
//! one, so a new call site has to say what it is encrypting and cannot inherit a blank.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::Hkdf;
use hmac::{Mac, SimpleHmac};
use rand::RngCore;
use sha2::Sha256;

#[derive(Debug, thiserror::Error)]
pub enum AeadError {
    #[error("MASTER_KEY env var not set")]
    KeyMissing,
    #[error("MASTER_KEY must be 32 bytes (got {0})")]
    KeyLength(usize),
    #[error("MASTER_KEY base64 decode failed: {0}")]
    KeyDecode(String),
    #[error("ciphertext too short")]
    Truncated,
    #[error("decryption failed (tampered or wrong key)")]
    Decrypt,
}

/// What a ciphertext is, and whose. Becomes the AEAD's associated data, so a blob decrypts
/// only in the position it was written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose<'a> {
    /// A tenant's CA private key, in `tenant_secrets.ca_key_encrypted`.
    TenantCaKey { tenant_id: i64 },
    /// A tenant's bundle-signing private key, in `tenant_secrets.bundle_signing_key_encrypted`.
    TenantBundleSigningKey { tenant_id: i64 },
    /// One host's configuration override, in `host_overrides.patch_encrypted`.
    HostOverride { tenant_id: i64, host_id: &'a str },
}

impl Purpose<'_> {
    /// The associated data itself.
    ///
    /// Version-prefixed so the encoding can change without silently accepting the old one,
    /// and NUL-separated because every field in it is either an integer or a ULID — none
    /// can contain a NUL, so no pair of distinct purposes can encode identically.
    fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        out.extend_from_slice(b"nsclient-fleet/aead/v1");
        let mut field = |bytes: &[u8]| {
            out.push(0);
            out.extend_from_slice(bytes);
        };
        match self {
            Self::TenantCaKey { tenant_id } => {
                field(b"tenant_ca_key");
                field(tenant_id.to_string().as_bytes());
            }
            Self::TenantBundleSigningKey { tenant_id } => {
                field(b"tenant_bundle_signing_key");
                field(tenant_id.to_string().as_bytes());
            }
            Self::HostOverride { tenant_id, host_id } => {
                field(b"host_override");
                field(tenant_id.to_string().as_bytes());
                field(host_id.as_bytes());
            }
        }
        out
    }
}

#[derive(Clone)]
pub struct MasterKey(Key);

impl MasterKey {
    pub fn from_env() -> Result<Self, AeadError> {
        let raw = std::env::var("MASTER_KEY").map_err(|_| AeadError::KeyMissing)?;
        Self::from_b64(&raw)
    }

    pub fn from_b64(b64: &str) -> Result<Self, AeadError> {
        let bytes = STANDARD
            .decode(b64)
            .map_err(|e| AeadError::KeyDecode(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(AeadError::KeyLength(bytes.len()));
        }
        let key = Key::clone_from_slice(&bytes);
        Ok(Self(key))
    }

    pub fn generate_b64() -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        STANDARD.encode(bytes)
    }

    /// Encrypt with a random 12-byte nonce, bound to `purpose`.
    /// Output layout: nonce (12) || ciphertext || tag.
    pub fn encrypt(&self, purpose: Purpose<'_>, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&self.0);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let aad = purpose.aad();
        let ct = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .expect("aead encrypt should not fail");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    /// Decrypt, requiring the ciphertext to have been written for exactly this purpose.
    /// A blob moved to another row, host or tenant fails here rather than being served.
    pub fn decrypt(&self, purpose: Purpose<'_>, blob: &[u8]) -> Result<Vec<u8>, AeadError> {
        self.open(blob, &purpose.aad())
    }

    /// Decrypt a ciphertext written before purposes existed, i.e. with empty associated
    /// data. Only the one-time startup rewrite has any business calling this — see
    /// `fleet_server::tenant_setup::rebind_legacy_ciphertexts`.
    pub fn decrypt_unbound(&self, blob: &[u8]) -> Result<Vec<u8>, AeadError> {
        self.open(blob, b"")
    }

    /// An independent 32-byte key for `info`, by HKDF-SHA256 over the master key.
    ///
    /// The point is independence: using the master key's raw bytes directly as a MAC or
    /// JWT key means any weakness or leak on that path is a leak of the key that decrypts
    /// the database. A subkey derived here reveals nothing about the master key, and two
    /// subkeys reveal nothing about each other, so each use can be reasoned about alone.
    pub fn derive_subkey(&self, info: &str) -> [u8; 32] {
        let hk = Hkdf::<Sha256>::new(Some(b"nsclient-fleet/hkdf/v1"), self.0.as_slice());
        let mut out = [0u8; 32];
        hk.expand(info.as_bytes(), &mut out)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        out
    }

    /// HMAC-SHA256 under the subkey for `info`.
    ///
    /// For values that must change when their input changes but must not let anyone who
    /// sees the output work backwards to the input. A plain hash of a low-entropy secret
    /// — a password in a host override, say — is an offline guessing oracle for anyone who
    /// can read the hash, and the hash is served to every role.
    pub fn mac(&self, info: &str, data: &[u8]) -> [u8; 32] {
        let mut m = <SimpleHmac<Sha256> as Mac>::new_from_slice(&self.derive_subkey(info))
            .expect("HMAC accepts a 32-byte key");
        m.update(data);
        m.finalize().into_bytes().into()
    }

    fn open(&self, blob: &[u8], aad: &[u8]) -> Result<Vec<u8>, AeadError> {
        if blob.len() < 12 + 16 {
            return Err(AeadError::Truncated);
        }
        let cipher = ChaCha20Poly1305::new(&self.0);
        let nonce = Nonce::from_slice(&blob[..12]);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &blob[12..],
                    aad,
                },
            )
            .map_err(|_| AeadError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CA_A: Purpose<'static> = Purpose::TenantCaKey { tenant_id: 1 };
    const CA_B: Purpose<'static> = Purpose::TenantCaKey { tenant_id: 2 };

    #[test]
    fn roundtrip() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let pt = b"top secret CA private key";
        let ct = key.encrypt(CA_A, pt);
        assert_ne!(&ct[12..], pt);
        let back = key.decrypt(CA_A, &ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn tamper_rejected() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let mut ct = key.encrypt(CA_A, b"abc");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(key.decrypt(CA_A, &ct), Err(AeadError::Decrypt)));
    }

    #[test]
    fn a_ciphertext_does_not_decrypt_under_another_tenant() {
        // Swapping two tenants' encrypted CA keys would otherwise have one tenant's
        // certificates signed by the other's CA, with no key needed to do it.
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let ct = key.encrypt(CA_A, b"tenant 1's CA key");
        assert!(matches!(key.decrypt(CA_B, &ct), Err(AeadError::Decrypt)));
    }

    #[test]
    fn a_ciphertext_does_not_decrypt_under_another_purpose() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let ct = key.encrypt(CA_A, b"key material");
        assert!(matches!(
            key.decrypt(Purpose::TenantBundleSigningKey { tenant_id: 1 }, &ct),
            Err(AeadError::Decrypt)
        ));
    }

    #[test]
    fn an_override_does_not_decrypt_onto_another_host() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let mine = Purpose::HostOverride {
            tenant_id: 1,
            host_id: "01J0AAA",
        };
        let theirs = Purpose::HostOverride {
            tenant_id: 1,
            host_id: "01J0BBB",
        };
        let ct = key.encrypt(mine, b"{\"password\":\"hunter2\"}");
        assert!(matches!(key.decrypt(theirs, &ct), Err(AeadError::Decrypt)));
        // ...nor onto the same host id in a different tenant.
        let other_tenant = Purpose::HostOverride {
            tenant_id: 2,
            host_id: "01J0AAA",
        };
        assert!(matches!(
            key.decrypt(other_tenant, &ct),
            Err(AeadError::Decrypt)
        ));
    }

    #[test]
    fn purposes_never_encode_to_the_same_associated_data() {
        let all = [
            Purpose::TenantCaKey { tenant_id: 1 },
            Purpose::TenantCaKey { tenant_id: 11 },
            Purpose::TenantBundleSigningKey { tenant_id: 1 },
            Purpose::HostOverride {
                tenant_id: 1,
                host_id: "a",
            },
            Purpose::HostOverride {
                tenant_id: 11,
                host_id: "a",
            },
            Purpose::HostOverride {
                tenant_id: 1,
                host_id: "1a",
            },
        ];
        let mut seen = Vec::new();
        for p in all {
            let aad = p.aad();
            assert!(
                !seen.contains(&aad),
                "{p:?} collides with an earlier purpose"
            );
            seen.push(aad);
        }
    }

    #[test]
    fn unbound_ciphertexts_still_open_for_the_rewrite_path() {
        // What the startup rewrite relies on: rows written before purposes existed carry
        // empty associated data and must still be readable exactly once, to be rewritten.
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let legacy = {
            use chacha20poly1305::aead::Aead;
            let cipher = ChaCha20Poly1305::new(&key.0);
            let nonce_bytes = [7u8; 12];
            let ct = cipher
                .encrypt(Nonce::from_slice(&nonce_bytes), b"old secret".as_ref())
                .unwrap();
            let mut out = nonce_bytes.to_vec();
            out.extend_from_slice(&ct);
            out
        };
        assert_eq!(key.decrypt_unbound(&legacy).unwrap(), b"old secret");
        assert!(matches!(
            key.decrypt(CA_A, &legacy),
            Err(AeadError::Decrypt)
        ));
    }

    #[test]
    fn subkeys_are_distinct_stable_and_not_the_master_key() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let a = key.derive_subkey("one");
        let b = key.derive_subkey("two");
        assert_ne!(a, b, "different info must give different subkeys");
        assert_eq!(a, key.derive_subkey("one"), "derivation must be stable");
        assert_ne!(
            a.as_slice(),
            key.0.as_slice(),
            "a subkey must not be the master key itself"
        );
    }

    #[test]
    fn mac_hides_its_input_and_tracks_changes() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let a = key.mac("state-hash", b"password=hunter2");
        assert_eq!(a, key.mac("state-hash", b"password=hunter2"));
        assert_ne!(a, key.mac("state-hash", b"password=hunter3"));
        // A different purpose over the same bytes is a different value, so one use's
        // output can never be replayed as another's.
        assert_ne!(a, key.mac("something-else", b"password=hunter2"));

        // And it is not a plain digest of the input: without the key you cannot compute it,
        // which is what stops a reader guessing a low-entropy override offline.
        let plain: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(b"password=hunter2").into();
        assert_ne!(a, plain);
    }

    #[test]
    fn bad_key_length() {
        let bad = STANDARD.encode([0u8; 16]);
        assert!(matches!(
            MasterKey::from_b64(&bad),
            Err(AeadError::KeyLength(16))
        ));
    }
}
