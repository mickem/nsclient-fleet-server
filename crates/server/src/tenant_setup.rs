use anyhow::Result;
use fleet_core::tenant::Tenant;
use fleet_enrollment::generate_tenant_ca;
use fleet_storage::{Db, TenantRepo, TenantSecretsRepo};

use crate::AppState;

/// Generate (CA + bundle-signing key) for the tenant and persist them encrypted at rest.
/// Idempotent — if secrets already exist, no-op.
pub async fn ensure_secrets(state: &AppState, tenant: &Tenant) -> Result<()> {
    let secrets_repo = TenantSecretsRepo::new(&state.db);
    if secrets_repo.get_by_tenant(tenant.id).await?.is_some() {
        return Ok(());
    }

    let generated = generate_tenant_ca(&tenant.slug)?;
    let ca_key_enc = state
        .config
        .master_key
        .encrypt(generated.ca.key_pem.as_bytes());
    let bundle_key_enc = state
        .config
        .master_key
        .encrypt(generated.bundle_signing_key_pem.as_bytes());

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
