use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::crypto::digest::sha256_hex;
use fleet_core::crypto::encbundle;
use fleet_storage::BundlesRepo;
use serde::Serialize;

use crate::auth::AuthedUser;
use crate::AppState;

/// Read a request body, refusing it — without buffering the rest — once it passes `max`.
async fn read_body_bounded(
    body: axum::body::Body,
    max: usize,
) -> std::result::Result<Vec<u8>, String> {
    use futures_util::StreamExt;
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("unreadable body: {e}"))?;
        if buf.len() + chunk.len() > max {
            return Err("larger than the original".into());
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Whether `bytes` can stand in for encrypted `version` under a new name: the same key,
/// exactly the original's length (AES-GCM output is as long as its input, so re-sealing
/// the same plaintext keeps it), and not the original ciphertext itself — which would
/// still be bound to the old name and open nowhere under the new one. The server cannot
/// check the AAD; this is everything short of that. Returns the key fingerprint.
pub(super) fn check_resealed(
    version: &fleet_storage::BundleRow,
    bytes: &[u8],
) -> std::result::Result<String, String> {
    if i64::try_from(bytes.len()).ok() != Some(version.size_bytes) {
        return Err(format!(
            "version {}: the re-sealed bundle is not the same size as the original",
            version.version
        ));
    }
    let fingerprint = encbundle::parse_header(bytes)
        .map_err(|e| {
            format!(
                "version {}: not a valid encrypted bundle: {e}",
                version.version
            )
        })?
        .fingerprint_hex();
    // A rename never changes which key opens a bundle: agents provisioned with the old one
    // would stop opening it.
    if version.key_fingerprint.as_deref() != Some(fingerprint.as_str()) {
        return Err(format!(
            "version {} is sealed with key {}; it must be re-sealed with the same key",
            version.version,
            version.key_fingerprint.as_deref().unwrap_or("?")
        ));
    }
    if sha256_hex(bytes) == version.sha256 {
        return Err(format!(
            "version {}: this is the original ciphertext, not one sealed under the new name",
            version.version
        ));
    }
    Ok(fingerprint)
}

#[derive(Serialize)]
pub struct StagedView {
    pub staged_id: String,
}

/// `POST /api/bundles/:id/reseal` — stage one encrypted version, re-sealed in the browser
/// under the name it is about to be renamed to. The body is the raw ciphertext.
///
/// One version per request, so neither the browser nor the server ever holds more than one
/// at a time, and the body is bounded by the version it replaces. The staged file belongs
/// to no row until a rename names it; one that never does is removed by housekeeping.
pub async fn stage_reseal(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(bundle_id): Path<String>,
    body: axum::body::Body,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let version = match BundlesRepo::new(&state.db)
        .get(who.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "bundle not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundle lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if version.format == encbundle::FORMAT_PLAIN {
        return (
            StatusCode::BAD_REQUEST,
            "a plain bundle is renamed without re-sealing",
        )
            .into_response();
    }
    let max = usize::try_from(version.size_bytes).unwrap_or(0);
    let bytes = match read_body_bounded(body, max).await {
        Ok(b) => b,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("version {}: {e}", version.version),
            )
                .into_response()
        }
    };
    if let Err(e) = check_resealed(&version, &bytes) {
        return (StatusCode::BAD_REQUEST, e).into_response();
    }
    let staged_id = fleet_core::crypto::bundlesig::new_bundle_id();
    if let Err(e) = state
        .bundle_store
        .put(who.tenant_id, &staged_id, &bytes)
        .await
    {
        tracing::error!(error = %e, "bundle store put failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response();
    }
    Json(StagedView { staged_id }).into_response()
}
