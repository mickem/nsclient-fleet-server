//! What a bundle's Ed25519 signature actually covers.
//!
//! v1 signed the bare 32-byte SHA-256 of the bytes, which binds nothing about *which*
//! bundle those bytes are. The digest already pins the content, so a signature over it
//! alone said little more than "this tenant's server saw this blob once". Anyone who could
//! write to the database could re-advertise an old signed blob under a new name, version or
//! id and it would verify — only the encrypted format's AAD closed name and version, and
//! only for that format.
//!
//! v2 signs a canonical descriptor of the bundle's identity together with its digest, so a
//! signature is a statement about a specific bundle in a specific tenant rather than about
//! some bytes.
//!
//! The descriptor is NUL-separated, and every field in it is a ULID, an integer, or a token
//! from a grammar that excludes NUL (`valid_bundle_token` in the server's bundle module, and
//! `format` is one of two literals) — so no two distinct bundles can produce the same bytes.
//! Priority is deliberately absent: it belongs to a group assignment, not to the bundle, and
//! the same bundle legitimately carries different priorities in different groups.

/// Version prefix. Present so a future change to the shape is a verification failure rather
/// than a silent reinterpretation.
const DOMAIN: &[u8] = b"nsclient-fleet/bundle-sig/v2";

/// A fresh bundle id. Server-generated, like every other id the filesystem sees; it lives
/// here because the signature covers it, so minting it and signing it belong together.
pub fn new_bundle_id() -> String {
    ulid::Ulid::new().to_string()
}

/// A bundle's identity, as the signature covers it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BundleDescriptor<'a> {
    pub tenant_id: i64,
    pub bundle_id: &'a str,
    pub name: &'a str,
    pub version: &'a str,
    /// `plain` or `enc-v1`.
    pub format: &'a str,
    /// Lowercase hex SHA-256 of the stored bytes.
    pub sha256_hex: &'a str,
}

impl BundleDescriptor<'_> {
    /// The exact bytes that are signed and verified. Ed25519 hashes internally, so this is
    /// signed directly rather than being digested first.
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DOMAIN.len() + 128);
        out.extend_from_slice(DOMAIN);
        for field in [
            self.tenant_id.to_string().as_str(),
            self.bundle_id,
            self.name,
            self.version,
            self.format,
            self.sha256_hex,
        ] {
            out.push(0);
            out.extend_from_slice(field.as_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d<'a>(id: &'a str, name: &'a str, version: &'a str, sha: &'a str) -> BundleDescriptor<'a> {
        BundleDescriptor {
            tenant_id: 1,
            bundle_id: id,
            name,
            version,
            format: "plain",
            sha256_hex: sha,
        }
    }

    #[test]
    fn every_field_changes_the_signing_bytes() {
        let base = d("01J0A", "checks", "1.0.0", "ab");
        let bytes = base.to_signing_bytes();

        for other in [
            BundleDescriptor {
                tenant_id: 2,
                ..base
            },
            BundleDescriptor {
                bundle_id: "01J0B",
                ..base
            },
            BundleDescriptor {
                name: "secrets",
                ..base
            },
            BundleDescriptor {
                version: "1.0.1",
                ..base
            },
            BundleDescriptor {
                format: "enc-v1",
                ..base
            },
            BundleDescriptor {
                sha256_hex: "cd",
                ..base
            },
        ] {
            assert_ne!(
                bytes,
                other.to_signing_bytes(),
                "{other:?} must not share signing bytes with the original"
            );
        }
    }

    #[test]
    fn fields_cannot_be_run_together() {
        // The separator is what stops ("ab", "c") and ("a", "bc") colliding. Every field is
        // a ULID, an integer, or a token from a grammar with no NUL in it, so it holds.
        assert_ne!(
            d("x", "ab", "c", "00").to_signing_bytes(),
            d("x", "a", "bc", "00").to_signing_bytes()
        );
    }

    #[test]
    fn the_domain_prefix_is_present() {
        let bytes = d("x", "n", "v", "00").to_signing_bytes();
        assert!(bytes.starts_with(DOMAIN));
    }
}
