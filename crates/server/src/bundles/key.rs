use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_storage::TenantBundleKeysRepo;
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::AppState;

#[derive(Serialize, Deserialize)]
pub struct BundleKeyView {
    /// Hex fingerprint (16 chars) of the tenant's current bundle-encryption key, or null
    /// when none has been registered. Never the key itself — the server never sees that.
    pub fingerprint: Option<String>,
}

/// `GET /api/bundle-key` — the registered key fingerprint, so the UI can verify a pasted
/// key before encrypting with it.
pub async fn get_bundle_key(State(state): State<AppState>, who: AuthedUser) -> Response {
    match TenantBundleKeysRepo::new(&state.db)
        .get(who.tenant_id)
        .await
    {
        Ok(fingerprint) => Json(BundleKeyView { fingerprint }).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundle key get failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct SetBundleKeyBody {
    pub fingerprint: String,
}

/// `PUT /api/bundle-key` — register (or rotate to) a new key's fingerprint. The browser
/// generates the key and sends only this; existing bundles keep the fingerprint they were
/// encrypted under, which is how the UI can tell them apart after a rotation.
pub async fn set_bundle_key(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<SetBundleKeyBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let fp = body.fingerprint.trim().to_ascii_lowercase();
    if fp.len() != 16 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
        return (
            StatusCode::BAD_REQUEST,
            "fingerprint must be 16 hex characters",
        )
            .into_response();
    }
    if let Err(e) = TenantBundleKeysRepo::new(&state.db)
        .set(who.tenant_id, &fp, Some(who.user_id))
        .await
    {
        tracing::error!(error = %e, "bundle key set failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    }
    crate::admin::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "bundle_key.set",
        "tenant",
        &who.tenant_id.to_string(),
        Some(&serde_json::json!({ "fingerprint": fp })),
    )
    .await;
    Json(BundleKeyView {
        fingerprint: Some(fp),
    })
    .into_response()
}
