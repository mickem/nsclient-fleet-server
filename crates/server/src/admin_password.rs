//! Producing the argon2 hash that `ON_PREM_ADMIN_PASSWORD_HASH` holds.
//!
//! On-prem installs authenticate one administrator by password, and the hash is the way to
//! configure it that does not leave the password itself in an env file, a backup, a
//! `docker inspect`, or a configuration repository. Nothing generated that hash for the
//! operator until this existed: argon2 has no ubiquitous command-line tool, and the one
//! packaged on Debian defaults to parameters that are not the ones
//! [`argon2::Argon2::default`] verifies with. Since the binary already carries the
//! implementation it checks against at sign-in, it is also the right thing to produce the
//! hash — `nsclient-fleet --hash-password`.
//!
//! The verifier is [`crate::auth`]'s, and it reads every parameter out of the PHC string
//! rather than assuming today's defaults, so a hash made by an older build keeps working
//! after the defaults move.

use anyhow::{bail, Context, Result};
use argon2::password_hash::PasswordHasher;
use argon2::Argon2;

/// Hash `password` into a PHC string (`$argon2id$v=19$m=…,t=…,p=…$salt$hash`).
///
/// The salt is fresh per call, so hashing the same password twice gives different strings.
/// Both verify — the salt travels inside the PHC string.
pub fn hash(password: &str) -> Result<String> {
    if password.is_empty() {
        bail!("the password is empty");
    }
    Ok(Argon2::default()
        .hash_password(password.as_bytes())
        .map_err(|e| anyhow::anyhow!("{e}"))
        .context("hashing the password")?
        .to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::{phc::PasswordHash, PasswordVerifier};

    /// The round trip that matters: what this produces is what the sign-in path accepts.
    /// Verification here is spelled exactly as `verify_admin_password` spells it, so a
    /// change to either side that breaks the pair fails this test rather than locking an
    /// operator out of their own install.
    fn verifies(phc: &str, password: &str) -> bool {
        let parsed = PasswordHash::new(phc).expect("valid PHC string");
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed)
            .is_ok()
    }

    #[test]
    fn hash_verifies_against_the_password_it_was_made_from() {
        let phc = hash("correct horse battery staple").unwrap();
        assert!(phc.starts_with("$argon2id$"), "unexpected format: {phc}");
        assert!(verifies(&phc, "correct horse battery staple"));
    }

    #[test]
    fn hash_rejects_a_different_password() {
        let phc = hash("correct horse battery staple").unwrap();
        assert!(!verifies(&phc, "Correct horse battery staple"));
        assert!(!verifies(&phc, ""));
    }

    /// Two hashes of one password differ, and both verify. Worth pinning: an operator who
    /// runs the command twice and gets different output should be able to use either.
    #[test]
    fn each_hash_gets_a_fresh_salt() {
        let a = hash("same password").unwrap();
        let b = hash("same password").unwrap();
        assert_ne!(a, b);
        assert!(verifies(&a, "same password"));
        assert!(verifies(&b, "same password"));
    }

    #[test]
    fn an_empty_password_is_refused() {
        assert!(hash("").is_err());
    }

    /// A password with a `$` or a newline in it must not produce something that reads as a
    /// different PHC string, and must still verify.
    #[test]
    fn awkward_characters_survive() {
        let password = "a$b\nc\td — ünïcode";
        let phc = hash(password).unwrap();
        assert_eq!(phc.matches("$argon2id$").count(), 1);
        assert!(verifies(&phc, password));
    }

    /// A hash made by the build before the crypto-crate upgrade. An operator's
    /// `ON_PREM_ADMIN_PASSWORD_HASH` was made by whatever build they had then, and must keep
    /// signing them in.
    #[test]
    fn hashes_from_earlier_builds_still_verify() {
        const PHC: &str = "$argon2id$v=19$m=19456,t=2,p=1$xxBD+RMHsBLgEaVFCBigsA$bZXJZlJKlcy89Vg2+1xWP69hYgO8TBOS4gYwerHbMtE";
        assert!(verifies(PHC, "correct horse battery staple"));
        assert!(!verifies(PHC, "correct horse battery stapler"));
    }
}
