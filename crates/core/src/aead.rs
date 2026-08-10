use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

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

    /// Encrypt with random 12-byte nonce. Output layout: nonce (12) || ciphertext.
    pub fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let cipher = ChaCha20Poly1305::new(&self.0);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = cipher
            .encrypt(nonce, plaintext)
            .expect("aead encrypt should not fail");
        let mut out = Vec::with_capacity(12 + ct.len());
        out.extend_from_slice(&nonce_bytes);
        out.extend_from_slice(&ct);
        out
    }

    pub fn decrypt(&self, blob: &[u8]) -> Result<Vec<u8>, AeadError> {
        if blob.len() < 12 + 16 {
            return Err(AeadError::Truncated);
        }
        let cipher = ChaCha20Poly1305::new(&self.0);
        let nonce = Nonce::from_slice(&blob[..12]);
        cipher
            .decrypt(nonce, &blob[12..])
            .map_err(|_| AeadError::Decrypt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let pt = b"top secret CA private key";
        let ct = key.encrypt(pt);
        assert_ne!(&ct[12..], pt);
        let back = key.decrypt(&ct).unwrap();
        assert_eq!(back, pt);
    }

    #[test]
    fn tamper_rejected() {
        let key = MasterKey::from_b64(&MasterKey::generate_b64()).unwrap();
        let mut ct = key.encrypt(b"abc");
        let last = ct.len() - 1;
        ct[last] ^= 0x01;
        assert!(matches!(key.decrypt(&ct), Err(AeadError::Decrypt)));
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
