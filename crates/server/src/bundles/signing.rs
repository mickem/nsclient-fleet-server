use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use fleet_storage::TenantSecretsRepo;

use crate::AppState;

/// The tenant's Ed25519 bundle-signing key, unwrapped from the master key.
pub(crate) async fn load_tenant_signing_key(
    state: &AppState,
    tenant_id: i64,
) -> Result<SigningKey> {
    let secrets = TenantSecretsRepo::new(&state.db)
        .get_by_tenant(tenant_id)
        .await?
        .ok_or_else(|| anyhow!("tenant secrets missing for {tenant_id}"))?;
    let key_bytes = state.config.master_key.decrypt(
        fleet_core::crypto::aead::Purpose::TenantBundleSigningKey { tenant_id },
        &secrets.bundle_signing_key_encrypted,
    )?;
    let key_pem = std::str::from_utf8(&key_bytes).context("bundle key utf8")?;
    SigningKey::from_pkcs8_pem(key_pem).map_err(|e| anyhow!("ed25519 key parse: {e}"))
}

/// Sign a bundle's descriptor, base64.
///
/// The descriptor, not the bytes: a signature over the digest alone binds nothing about
/// *which* bundle those bytes are, so an old signed blob could be re-advertised under a new
/// name, version or id and still verify. See [`fleet_core::crypto::bundlesig`].
pub(crate) fn sign_descriptor(
    key: &SigningKey,
    descriptor: &fleet_core::crypto::bundlesig::BundleDescriptor<'_>,
) -> String {
    // Ed25519 hashes internally, so the descriptor is signed directly rather than digested
    // first — one fewer step for an agent implementation to get wrong.
    STANDARD.encode(key.sign(&descriptor.to_signing_bytes()).to_bytes())
}

/// Load the tenant key and sign one descriptor. For paths that sign once; loading the key
/// decrypts it, so a path signing many loads it once and uses [`sign_descriptor`].
pub(crate) async fn sign_with_tenant_key(
    state: &AppState,
    tenant_id: i64,
    descriptor: &fleet_core::crypto::bundlesig::BundleDescriptor<'_>,
) -> Result<String> {
    Ok(sign_descriptor(
        &load_tenant_signing_key(state, tenant_id).await?,
        descriptor,
    ))
}
