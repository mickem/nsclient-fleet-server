use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// HKDF label for the bootstrap-token signing key, when it is derived from `MASTER_KEY`
/// rather than set explicitly. Lives here so the derivation and the tokens it signs cannot
/// drift apart.
pub const BOOTSTRAP_JWT_INFO: &str = "bootstrap-jwt/v1";

/// What these tokens are for. Validated on decode, so a token minted for some other purpose
/// under the same key — a future one, a token from a different deployment's tooling — is
/// not silently accepted as an enrollment token. Cheap to add now, impossible to add later
/// without a flag day.
const AUDIENCE: &str = "nsclient-fleet/enroll";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapClaims {
    pub host_id: String,
    pub tenant_id: i64,
    pub nonce: String,
    pub exp: usize,
    pub iat: usize,
    /// Always [`AUDIENCE`] on tokens we mint. Defaulted on deserialize so a token issued
    /// before the claim existed still parses — and is then refused by the validator, which
    /// is the right outcome: those tokens live for an hour, so the window in which anyone
    /// holds one is over long before an upgrade finishes rolling out.
    #[serde(default)]
    pub aud: String,
}

pub fn encode_bootstrap(secret: &[u8], claims: &BootstrapClaims) -> String {
    let claims = BootstrapClaims {
        aud: AUDIENCE.to_string(),
        ..claims.clone()
    };
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret),
    )
    .expect("jwt encode should not fail")
}

pub fn decode_bootstrap(
    secret: &[u8],
    token: &str,
) -> Result<BootstrapClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::HS256);
    validation.set_required_spec_claims(&["exp", "aud"]);
    validation.set_audience(&[AUDIENCE]);
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
            aud: String::new(),
        };
        let token = encode_bootstrap(secret, &c);
        let back = decode_bootstrap(secret, &token).unwrap();
        assert_eq!(back.host_id, "01HXXX");
        assert_eq!(back.tenant_id, 1);
        assert_eq!(back.aud, AUDIENCE, "minting always stamps the audience");
    }

    #[test]
    fn rejects_a_token_minted_for_another_audience() {
        let secret = b"some-secret-bytes-32-bytes-aaaaa";
        let c = BootstrapClaims {
            host_id: "x".into(),
            tenant_id: 1,
            nonce: "n".into(),
            iat: now(),
            exp: now() + 60,
            aud: "somewhere-else".into(),
        };
        // Encode without going through `encode_bootstrap`, which would stamp our audience.
        let token = encode(
            &Header::new(Algorithm::HS256),
            &c,
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(decode_bootstrap(secret, &token).is_err());
    }

    #[test]
    fn rejects_a_token_with_no_audience_at_all() {
        let secret = b"some-secret-bytes-32-bytes-aaaaa";
        #[derive(Serialize)]
        struct Old {
            host_id: String,
            tenant_id: i64,
            nonce: String,
            exp: usize,
            iat: usize,
        }
        let token = encode(
            &Header::new(Algorithm::HS256),
            &Old {
                host_id: "x".into(),
                tenant_id: 1,
                nonce: "n".into(),
                exp: now() + 60,
                iat: now(),
            },
            &EncodingKey::from_secret(secret),
        )
        .unwrap();
        assert!(decode_bootstrap(secret, &token).is_err());
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
            aud: String::new(),
        };
        let token = encode_bootstrap(secret, &c);
        assert!(decode_bootstrap(secret, &token).is_err());
    }
}
