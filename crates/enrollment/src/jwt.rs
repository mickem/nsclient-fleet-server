use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapClaims {
    pub host_id: String,
    pub tenant_id: i64,
    pub nonce: String,
    pub exp: usize,
    pub iat: usize,
}

pub fn encode_bootstrap(secret: &[u8], claims: &BootstrapClaims) -> String {
    encode(
        &Header::new(Algorithm::HS256),
        claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("jwt encode should not fail")
}

pub fn decode_bootstrap(
    secret: &[u8],
    token: &str,
) -> Result<BootstrapClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp"]);
    let data = decode::<BootstrapClaims>(token, &DecodingKey::from_secret(secret), &validation)?;
    Ok(data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> usize {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize
    }

    #[test]
    fn roundtrip() {
        let secret = b"some-secret-bytes-32-bytes-aaaaa";
        let c = BootstrapClaims {
            host_id: "01HXXX".into(),
            tenant_id: 1,
            nonce: "abc".into(),
            iat: now(),
            exp: now() + 60,
        };
        let token = encode_bootstrap(secret, &c);
        let back = decode_bootstrap(secret, &token).unwrap();
        assert_eq!(back.host_id, "01HXXX");
        assert_eq!(back.tenant_id, 1);
    }

    #[test]
    fn rejects_expired() {
        let secret = b"some-secret-bytes-32-bytes-aaaaa";
        let c = BootstrapClaims {
            host_id: "x".into(),
            tenant_id: 1,
            nonce: "n".into(),
            iat: now() - 1000,
            exp: now() - 600, // beyond jsonwebtoken's default 60s leeway
        };
        let token = encode_bootstrap(secret, &c);
        assert!(decode_bootstrap(secret, &token).is_err());
    }
}
