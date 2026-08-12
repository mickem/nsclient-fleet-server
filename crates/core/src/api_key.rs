use serde::{Deserialize, Serialize};

/// A long-lived bearer token bound to a user.
///
/// The secret itself is never held here — only its hash reaches storage, and only the prefix
/// comes back out. An `ApiKey` is the *record* of a key, which is all the API can ever show
/// once the token has been handed over.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: String,
    pub tenant_id: i64,
    pub user_id: i64,
    /// Operator-supplied label. The only way to tell two keys apart in a list.
    pub name: String,
    /// Leading characters of the token, for recognising it. Not a secret and not sufficient
    /// to authenticate — see `TOKEN_PREFIX_LEN`.
    pub token_prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
}

/// Every token starts with this, so one found in a log or a script is identifiable at a
/// glance as a fleet credential.
pub const TOKEN_PREFIX: &str = "nsk_";

/// How much of the token is stored in the clear for display. Eight characters of base64 is
/// 48 bits — enough to distinguish keys in a list, far too little to guess the remaining
/// ~208 bits.
pub const TOKEN_PREFIX_LEN: usize = TOKEN_PREFIX.len() + 8;

/// The displayable head of a token, e.g. `nsk_a1B2c3D4`.
pub fn prefix_of(token: &str) -> String {
    token.chars().take(TOKEN_PREFIX_LEN).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_is_short_and_stable() {
        let token = format!("{TOKEN_PREFIX}abcdefghijklmnop");
        assert_eq!(prefix_of(&token), "nsk_abcdefgh");
        assert_eq!(prefix_of(&token).len(), TOKEN_PREFIX_LEN);
    }

    /// A token shorter than the prefix length must not panic or over-read — `prefix_of` is
    /// applied to whatever arrives on the wire.
    #[test]
    fn short_tokens_are_truncated_not_padded() {
        assert_eq!(prefix_of("nsk_"), "nsk_");
        assert_eq!(prefix_of(""), "");
    }
}
