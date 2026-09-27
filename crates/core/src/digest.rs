//! The one SHA-256-as-hex helper. Bundle digests, facts hashes and stored token hashes are
//! all lowercase hex SHA-256, and they have to agree byte for byte with what agents compute,
//! so there is exactly one spelling of it.

use sha2::{Digest, Sha256};

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// Lowercase hex of `bytes`, two digits a byte.
pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[usize::from(b >> 4)] as char);
        out.push(HEX[usize::from(b & 0xf)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_is_two_lowercase_digits_a_byte() {
        assert_eq!(hex(&[]), "");
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
    }

    #[test]
    fn known_digests() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            sha256_hex(b"{}"),
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
        );
    }
}
