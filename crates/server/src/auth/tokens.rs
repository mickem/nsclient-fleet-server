use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::RngCore;

/// Generate a 256-bit random token, URL-safe base64-encoded (~43 chars).
pub fn random_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// SHA-256 of a token, hex-encoded for stable string storage.
pub fn hash_token(token: &str) -> String {
    fleet_core::digest::sha256_hex(token.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_is_distinct_each_call() {
        let a = random_token();
        let b = random_token();
        assert_ne!(a, b);
        assert!(a.len() >= 40);
    }

    #[test]
    fn hash_is_deterministic() {
        assert_eq!(hash_token("hello"), hash_token("hello"));
        assert_ne!(hash_token("hello"), hash_token("world"));
    }
}
