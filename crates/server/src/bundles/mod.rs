//! Bundle upload, signing, assignment to groups, and mTLS delivery (Phase 5c).
//!
//! - [`store`] keeps the bytes; rows live in `fleet_storage::BundlesRepo`.
//! - [`upload`] and [`compose`] make bundles; [`archive`] is the zip and `bundle.toml` they
//!   read and write.
//! - [`rename`] and [`reseal`] change existing ones; [`signing`] signs what every path stores.
//! - [`assign`] puts bundles on groups, [`download`] hands them to the UI and to agents, and
//!   [`key`] is the tenant's registered bundle-encryption key.

mod archive;
mod assign;
mod compose;
mod download;
mod key;
mod rename;
mod reseal;
mod signing;
mod store;
mod upload;

pub(crate) use archive::{
    build_zip_from_entries, path_clash, read_zip_entries, MAX_INFLATED_TOTAL, MAX_ZIP_ENTRIES,
};
pub use assign::{
    assign_to_group, list_for_group, unassign_from_group, AssignBody, AssignmentView,
};
pub use compose::{compose, get_config, BundleConfigView, ComposeBody};
pub use download::{download, ui_download};
pub use key::{get_bundle_key, set_bundle_key, BundleKeyView, SetBundleKeyBody};
pub use rename::{rename, RenameBody};
pub use reseal::{stage_reseal, StagedView};
pub(crate) use signing::{
    load_signing_key, load_tenant_signing_key, sign_descriptor, sign_with_tenant_key,
};
pub use store::{BundleStore, LocalBundleStore, StoredBundleFile};
pub use upload::upload;

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_storage::BundlesRepo;
use serde::Serialize;

use crate::auth::AuthedUser;
use crate::AppState;

#[derive(Serialize)]
pub struct BundleView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub signature: String,
    pub uploaded_at: i64,
    /// `plain` or `enc-v1`. Encrypted bundles are client-side AES-256-GCM envelopes the
    /// server cannot read or edit — see `fleet_core::crypto::encbundle`.
    pub format: String,
    pub key_fingerprint: Option<String>,
}

impl From<fleet_storage::BundleRow> for BundleView {
    fn from(b: fleet_storage::BundleRow) -> Self {
        Self {
            id: b.id,
            name: b.name,
            version: b.version,
            sha256: b.sha256,
            size_bytes: b.size_bytes,
            signature: b.signature,
            uploaded_at: b.uploaded_at,
            format: b.format,
            key_fingerprint: b.key_fingerprint,
        }
    }
}

/// Shared refusal text, so upload and compose say the same thing.
const BUNDLE_TOKEN_RULE: &str =
    "name and version must be 1-128 characters of letters, digits, '.', '_' or '-'";

pub(crate) fn valid_bundle_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `DELETE /api/bundles/:id` — remove a bundle, its assignments and its bytes.
///
/// There was no way to delete one at all, which is why the disk only ever grew. Assignments
/// go in the same transaction: a group left pointing at a bundle that is not there fails
/// desired-state computation for every host in it.
pub async fn delete_bundle(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(bundle_id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if let Some(refused) = crate::config_source::refuse_if_managed(&state, who.tenant_id) {
        return refused;
    }
    let bundles = BundlesRepo::new(&state.db);
    let row = match bundles.get(who.tenant_id, &bundle_id).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "bundle not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundle lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    match bundles.delete(who.tenant_id, &bundle_id).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "bundle not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundle delete failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    }

    // After the row, not before: a file with no row is wasted disk, a row with no file is a
    // bundle that 500s on download. If this fails the row is still gone and the file is
    // orphaned, which is the direction to fail in.
    if let Err(e) = state.bundle_store.delete(who.tenant_id, &bundle_id).await {
        tracing::error!(error = %e, %bundle_id, "bundle bytes could not be removed");
    }

    // Assignments changed, so every host's memoized state may have.
    crate::hosts::config_api::bump_config_version(&state, who.tenant_id).await;

    crate::admin::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "bundle.deleted",
        "bundle",
        &bundle_id,
        Some(&serde_json::json!({ "name": row.name, "version": row.version })),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

pub async fn list(State(state): State<AppState>, who: AuthedUser) -> Response {
    let bundles = BundlesRepo::new(&state.db);
    match bundles.list(who.tenant_id).await {
        Ok(rows) => {
            Json(rows.into_iter().map(BundleView::from).collect::<Vec<_>>()).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "bundles list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}
