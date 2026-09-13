use anyhow::{Context, Result};
use fleet_core::aead::Purpose;
use fleet_core::tenant::Tenant;
use fleet_enrollment::generate_tenant_ca;
use fleet_storage::{Db, HostOverridesRepo, TenantRepo, TenantSecretsRepo};

use crate::AppState;

/// Generate (CA + bundle-signing key) for the tenant and persist them encrypted at rest.
/// Idempotent — if secrets already exist, no-op.
pub async fn ensure_secrets(state: &AppState, tenant: &Tenant) -> Result<()> {
    let secrets_repo = TenantSecretsRepo::new(&state.db);
    if secrets_repo.get_by_tenant(tenant.id).await?.is_some() {
        return Ok(());
    }

    let generated = generate_tenant_ca(&tenant.slug)?;
    let ca_key_enc = state.config.master_key.encrypt(
        Purpose::TenantCaKey {
            tenant_id: tenant.id,
        },
        generated.ca.key_pem.as_bytes(),
    );
    let bundle_key_enc = state.config.master_key.encrypt(
        Purpose::TenantBundleSigningKey {
            tenant_id: tenant.id,
        },
        generated.bundle_signing_key_pem.as_bytes(),
    );

    secrets_repo
        .create(
            tenant.id,
            &generated.ca.cert_pem,
            &ca_key_enc,
            &generated.ca.subject_dn,
            &generated.bundle_signing_pub_pem,
            &bundle_key_enc,
        )
        .await?;
    tracing::info!(tenant_id = tenant.id, slug = %tenant.slug, "tenant secrets generated");
    Ok(())
}

/// Re-encrypt ciphertexts written before they were bound to a purpose.
///
/// Rows created by an earlier version carry empty associated data, so they still decrypt
/// under any purpose — which is the whole weakness. They cannot be rewritten by a SQL
/// migration, since that would mean decrypting, so it happens here at startup, once: a row
/// that already opens under its own purpose is left alone, and one that only opens unbound
/// is written back bound. After the first start on a given database this walk finds nothing
/// and costs two reads.
///
/// A row that opens under neither is left untouched and logged. That is a wrong
/// `MASTER_KEY` or a genuinely corrupt row, and quietly overwriting it would destroy the
/// only copy of a tenant's CA key.
pub async fn rebind_legacy_ciphertexts(state: &AppState, db: &Db) -> Result<()> {
    let key = &state.config.master_key;
    let mut rewritten = 0usize;

    let secrets_repo = TenantSecretsRepo::new(db);
    for ca in secrets_repo.list_all_cas().await? {
        let tenant_id = ca.tenant_id;
        let Some(stored) = secrets_repo.get_by_tenant(tenant_id).await? else {
            continue;
        };
        let ca_purpose = Purpose::TenantCaKey { tenant_id };
        let sign_purpose = Purpose::TenantBundleSigningKey { tenant_id };

        let ca_bound = key.decrypt(ca_purpose, &stored.ca_key_encrypted).is_ok();
        let sign_bound = key
            .decrypt(sign_purpose, &stored.bundle_signing_key_encrypted)
            .is_ok();
        if ca_bound && sign_bound {
            continue;
        }

        // Both columns are rewritten together or neither is, so a crash between them
        // cannot leave a tenant half-converted in a way the next pass misreads.
        let ca_plain = match if ca_bound {
            key.decrypt(ca_purpose, &stored.ca_key_encrypted)
        } else {
            key.decrypt_unbound(&stored.ca_key_encrypted)
        } {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(tenant_id, error = %e, "tenant CA key opens under no known binding — left untouched. Check MASTER_KEY.");
                continue;
            }
        };
        let sign_plain = match if sign_bound {
            key.decrypt(sign_purpose, &stored.bundle_signing_key_encrypted)
        } else {
            key.decrypt_unbound(&stored.bundle_signing_key_encrypted)
        } {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(tenant_id, error = %e, "tenant bundle-signing key opens under no known binding — left untouched. Check MASTER_KEY.");
                continue;
            }
        };

        secrets_repo
            .replace_encrypted_keys(
                tenant_id,
                &key.encrypt(ca_purpose, &ca_plain),
                &key.encrypt(sign_purpose, &sign_plain),
            )
            .await?;
        rewritten += 1;
    }

    let overrides_repo = HostOverridesRepo::new(db);
    for (tenant_id, host_id, blob) in overrides_repo.list_all().await? {
        let purpose = Purpose::HostOverride {
            tenant_id,
            host_id: &host_id,
        };
        if key.decrypt(purpose, &blob).is_ok() {
            continue;
        }
        match key.decrypt_unbound(&blob) {
            Ok(plain) => {
                overrides_repo
                    .replace_ciphertext(tenant_id, &host_id, &key.encrypt(purpose, &plain))
                    .await?;
                rewritten += 1;
            }
            Err(e) => tracing::error!(
                tenant_id,
                %host_id,
                error = %e,
                "host override opens under no known binding — left untouched. Check MASTER_KEY."
            ),
        }
    }

    if rewritten > 0 {
        tracing::info!(
            rewritten,
            "bound stored ciphertexts to their tenant and purpose"
        );
    }
    Ok(())
}

/// Re-sign bundles whose signature predates the descriptor.
///
/// v1 signed the bare digest, which says nothing about which bundle those bytes are. The
/// fields the v2 descriptor needs are all on the row, so no stored bytes are read — a row
/// whose signature already verifies is skipped, and one that does not is re-signed. After
/// the first start on a given database this walk costs one signature verification per
/// bundle and no writes.
pub async fn resign_bundles(state: &AppState, db: &Db) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    let bundles = fleet_storage::BundlesRepo::new(db);
    let secrets = TenantSecretsRepo::new(db);
    let mut resigned = 0usize;

    for row in bundles.list_all().await? {
        let descriptor = fleet_core::bundlesig::BundleDescriptor {
            tenant_id: row.tenant_id,
            bundle_id: &row.id,
            name: &row.name,
            version: &row.version,
            format: &row.format,
            sha256_hex: &row.sha256,
        };

        // Verify with the tenant's public key rather than re-signing unconditionally: the
        // signing key is only needed for rows that actually need rewriting.
        let already_valid = match secrets.get_by_tenant(row.tenant_id).await? {
            Some(sec) => {
                use ed25519_dalek::pkcs8::DecodePublicKey;
                match (
                    VerifyingKey::from_public_key_pem(&sec.bundle_signing_pub_pem),
                    base64_decode(&row.signature),
                ) {
                    (Ok(vk), Some(sig)) => Signature::from_slice(&sig)
                        .map(|sig| vk.verify(&descriptor.to_signing_bytes(), &sig).is_ok())
                        .unwrap_or(false),
                    _ => false,
                }
            }
            None => {
                tracing::error!(
                    tenant_id = row.tenant_id,
                    "bundle belongs to a tenant with no secrets — cannot re-sign"
                );
                continue;
            }
        };
        if already_valid {
            continue;
        }

        let signature = crate::bundles::sign_with_tenant_key(state, row.tenant_id, &descriptor)
            .await
            .with_context(|| format!("re-sign bundle {}", row.id))?;
        bundles
            .replace_signature(row.tenant_id, &row.id, &signature)
            .await?;
        resigned += 1;
    }

    if resigned > 0 {
        tracing::info!(
            resigned,
            "re-signed bundles whose signature covered only their digest"
        );
    }
    Ok(())
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    STANDARD.decode(s).ok()
}

/// Backfill secrets for any tenants that pre-date Phase 3 (i.e., were created before the
/// signup hook started generating secrets, or via the on-prem admin bootstrap).
pub async fn backfill_all(state: &AppState, db: &Db) -> Result<()> {
    let tenants = TenantRepo::new(db);
    let secrets_repo = TenantSecretsRepo::new(db);

    let existing: Vec<i64> = secrets_repo
        .list_all_cas()
        .await?
        .into_iter()
        .map(|c| c.tenant_id)
        .collect();

    // Iterate by listing tenants — for v1 we expect single-digit on-prem tenants and a
    // bounded SaaS count; if this ever needs paging we'll add it then.
    let all_ids: Vec<i64> = sqlx::query_scalar("SELECT id FROM tenants ORDER BY id")
        .fetch_all(&db.read)
        .await?;

    for tenant_id in all_ids {
        if existing.contains(&tenant_id) {
            continue;
        }
        let tenant = tenants
            .get(tenant_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("tenant {tenant_id} disappeared during backfill"))?;
        ensure_secrets(state, &tenant).await?;
    }
    Ok(())
}
