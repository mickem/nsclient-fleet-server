use axum::{
    extract::{Multipart, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::crypto::digest::sha256_hex;
use fleet_core::crypto::encbundle;
use fleet_storage::{BundlesRepo, TenantRepo};

use super::{sign_with_tenant_key, valid_bundle_token, BundleView, BUNDLE_TOKEN_RULE};
use crate::auth::AuthedUser;
use crate::AppState;

/// `POST /api/bundles` — multipart upload. Required parts:
///   - `name` (text)
///   - `version` (text)
///   - `bundle` (file: zip OR raw bytes; we don't unpack — opaque blob from server's view)
///
/// Optional:
///   - `format` (text): `plain` (default) or `enc-v1` for a client-side encrypted NSEB1
///     envelope.
///   - `base_bundle_id` (text): the bundle this one was edited from. It must still exist
///     under the same name: an editor left open across a rename would otherwise save the
///     old name back and split the bundle in two. Encrypted uploads are validated structurally (magic + header) and their
///     key fingerprint recorded; the server can neither read nor produce their contents.
pub async fn upload(
    State(state): State<AppState>,
    who: AuthedUser,
    mut form: Multipart,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if let Some(refused) = crate::config_source::refuse_if_managed(&state, who.tenant_id) {
        return refused;
    }
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut format: Option<String> = None;
    let mut base_bundle_id: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = form.next_field().await {
        match field.name().unwrap_or("").to_string().as_str() {
            "name" => name = field.text().await.ok(),
            "version" => version = field.text().await.ok(),
            "format" => format = field.text().await.ok(),
            "base_bundle_id" => base_bundle_id = field.text().await.ok(),
            "bundle" => {
                bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            _ => {}
        }
    }

    // The same grammar compose enforces. Raw upload only checked non-empty, which mattered
    // for more than tidiness: the encrypted-bundle AAD is `name || 0x00 || version`, so a
    // name containing a NUL collides with a different (name, version) pair and the binding
    // stops distinguishing them. NULs and newlines also flowed straight into audit JSON and
    // the console from here.
    let name = match name.as_deref().map(str::trim) {
        Some(n) if valid_bundle_token(n) => n.to_string(),
        _ => return (StatusCode::BAD_REQUEST, BUNDLE_TOKEN_RULE).into_response(),
    };
    let version = match version.as_deref().map(str::trim) {
        Some(v) if valid_bundle_token(v) => v.to_string(),
        _ => return (StatusCode::BAD_REQUEST, BUNDLE_TOKEN_RULE).into_response(),
    };
    let bytes = match bytes {
        Some(b) if !b.is_empty() => b,
        _ => return (StatusCode::BAD_REQUEST, "missing or empty bundle").into_response(),
    };
    if let Some(base_id) = base_bundle_id.as_deref().filter(|s| !s.is_empty()) {
        match BundlesRepo::new(&state.db)
            .get(who.tenant_id, base_id)
            .await
        {
            Ok(Some(base)) if base.name == name => {}
            Ok(Some(base)) => {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "the bundle you were editing has been renamed to '{}' — reopen it",
                        base.name
                    ),
                )
                    .into_response()
            }
            Ok(None) => {
                return (
                    StatusCode::NOT_FOUND,
                    "the bundle you were editing is gone (renamed or deleted) — reopen it",
                )
                    .into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "base bundle lookup failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }

    let format = match format.as_deref().map(str::trim) {
        None | Some("") | Some(encbundle::FORMAT_PLAIN) => encbundle::FORMAT_PLAIN,
        Some(encbundle::FORMAT_ENC_V1) => encbundle::FORMAT_ENC_V1,
        Some(other) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("unknown format '{other}' (expected 'plain' or 'enc-v1')"),
            )
                .into_response();
        }
    };

    // Keep the declared format and the bytes unambiguous in both directions: agents treat
    // the NSEB1 magic as authoritative, so a mislabeled blob must never be stored.
    let key_fingerprint = if format == encbundle::FORMAT_ENC_V1 {
        match encbundle::parse_header(&bytes) {
            Ok(h) => Some(h.fingerprint_hex()),
            Err(e) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("not a valid encrypted bundle: {e}"),
                )
                    .into_response();
            }
        }
    } else {
        if encbundle::is_encrypted(&bytes) {
            return (
                StatusCode::BAD_REQUEST,
                "bundle carries the encrypted-bundle magic but format is 'plain' — upload with format=enc-v1",
            )
                .into_response();
        }
        None
    };

    match persist_bundle(
        &state,
        &who,
        &name,
        &version,
        bytes,
        format,
        key_fingerprint.as_deref(),
        "bundle.uploaded",
    )
    .await
    {
        Ok(view) => Json(view).into_response(),
        Err(resp) => resp,
    }
}

/// Shared tail of every bundle-creating path: tier size check, sign with the tenant key,
/// insert the row, store the bytes, bump config_version, audit. Returns the error as a
/// ready-to-send Response so handlers stay thin.
// result_large_err: the Err is a ready-to-send Response by design; one upload per call,
// so the size is irrelevant next to the multipart body it follows.
#[allow(clippy::too_many_arguments, clippy::result_large_err)]
pub(super) async fn persist_bundle(
    state: &AppState,
    who: &AuthedUser,
    name: &str,
    version: &str,
    bytes: Vec<u8>,
    format: &str,
    key_fingerprint: Option<&str>,
    audit_action: &str,
) -> std::result::Result<BundleView, Response> {
    let tenant = match TenantRepo::new(&state.db).get(who.tenant_id).await {
        Ok(Some(t)) => t,
        _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "tenant missing").into_response()),
    };
    let limits = fleet_core::tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());

    // Bundles are immutable and, until now, undeletable, so uploading was a one-way ratchet
    // on disk: a config writer could fill the volume and nothing would ever reclaim it. The
    // per-bundle size cap did not help, because nothing capped the count.
    match BundlesRepo::new(&state.db).count(who.tenant_id).await {
        Ok(n) if n as u64 >= limits.max_bundles as u64 => {
            return Err((
                StatusCode::FORBIDDEN,
                Json(crate::hosts::TierLimitError {
                    error: "tier_limit",
                    limit: limits.max_bundles,
                    current: n,
                    tier: limits.name.to_string(),
                }),
            )
                .into_response());
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "bundle count failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response());
        }
    }

    let max = (limits.max_bundle_mb as usize) * 1024 * 1024;
    if bytes.len() > max {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("bundle exceeds tier limit ({} MB)", limits.max_bundle_mb),
        )
            .into_response());
    }

    let sha = sha256_hex(&bytes);

    // The id is chosen here rather than by the insert, because the signature covers it —
    // see `fleet_core::crypto::bundlesig` for why a signature over the digest alone was worth so
    // little.
    let bundle_id = fleet_core::crypto::bundlesig::new_bundle_id();
    let descriptor = fleet_core::crypto::bundlesig::BundleDescriptor {
        tenant_id: who.tenant_id,
        bundle_id: &bundle_id,
        name,
        version,
        format,
        sha256_hex: &sha,
    };
    let signature_b64 = match sign_with_tenant_key(state, who.tenant_id, &descriptor).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "bundle sign failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response());
        }
    };

    let bundles = BundlesRepo::new(&state.db);
    let row = match bundles
        .create(
            &bundle_id,
            who.tenant_id,
            name,
            version,
            &sha,
            bytes.len() as i64,
            &signature_b64,
            format,
            key_fingerprint,
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::info!(error = %e, "bundle create failed");
            return Err((StatusCode::CONFLICT, "(name, version) already exists").into_response());
        }
    };

    if let Err(e) = state.bundle_store.put(who.tenant_id, &row.id, &bytes).await {
        tracing::error!(error = %e, "bundle store put failed");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response());
    }

    if let Err(e) = TenantRepo::new(&state.db)
        .bump_config_version(who.tenant_id)
        .await
    {
        tracing::error!(error = %e, "config_version bump failed");
    }

    crate::admin::audit::record(
        state,
        who.tenant_id,
        Some(who.user_id),
        audit_action,
        "bundle",
        &row.id,
        Some(&serde_json::json!({
            "name": row.name,
            "version": row.version,
            "size_bytes": row.size_bytes,
            "sha256": row.sha256,
            "format": row.format,
        })),
    )
    .await;

    Ok(row.into())
}
