use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::crypto::digest::sha256_hex;
use fleet_core::crypto::encbundle;
use fleet_storage::{BundlesRepo, MovedBundle, RenameOutcome, RenamedInPlace};
use serde::Deserialize;

use super::reseal::check_resealed;
use super::{
    load_tenant_signing_key, sign_descriptor, valid_bundle_token, BundleView, BUNDLE_TOKEN_RULE,
};
use crate::auth::AuthedUser;
use crate::AppState;

/// A bundle id as the server mints them (a ULID). Checked before an id from a request is
/// used as a file name: the bundle token grammar allows `..`, this does not.
fn valid_bundle_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

#[derive(Deserialize)]
pub struct RenameBody {
    /// The current name, exactly as stored.
    pub from: String,
    pub to: String,
    /// For each encrypted version of `from`: its id → the id `reseal` staged for it.
    #[serde(default)]
    pub resealed: std::collections::BTreeMap<String, String>,
}

/// `POST /api/bundles/rename` — rename every version of a bundle.
///
/// Plain versions are renamed in place: same id, same bytes, re-signed over the sha256 the
/// row recorded at upload. The bytes are never read, so whatever is on disk is never
/// vouched for anew — a file changed since upload still fails the agent's digest check.
/// The zip's bundle.toml keeps the name it was built with; agents never read it, and the
/// next edit rewrites it.
///
/// Encrypted versions bind the name into their AAD, so each needs new ciphertext, staged
/// first through `reseal` (only the browser holds the key to produce it); here each staged
/// file is checked again, one at a time, and the version moves to it under the staged id
/// along with its group assignments. The replaced ciphertext is left for housekeeping, so
/// an agent mid-download of it is not cut off.
///
/// Every group carries the same versions as before, and every host carrying the bundle
/// gets a new desired-state hash (it covers the whole signed descriptor). All or nothing:
/// a rename that would leave some versions behind is refused.
pub async fn rename(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<RenameBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if let Some(refused) = crate::config_source::refuse_if_managed(&state, who.tenant_id) {
        return refused;
    }
    // `from` is matched exactly as stored: a bundle uploaded before names were validated
    // is the one most worth renaming, and must not be refused for the name it has.
    let from = body.from;
    let to = body.to.trim().to_string();
    if from.is_empty() {
        return (StatusCode::BAD_REQUEST, "missing 'from'").into_response();
    }
    if !valid_bundle_token(&to) {
        return (StatusCode::BAD_REQUEST, BUNDLE_TOKEN_RULE).into_response();
    }
    if from == to {
        return (StatusCode::BAD_REQUEST, "the new name is the current name").into_response();
    }
    let bundles = BundlesRepo::new(&state.db);
    let internal = |e: anyhow::Error| {
        tracing::error!(error = %e, "bundle rename failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
    };
    match bundles.list_by_name(who.tenant_id, &to).await {
        Ok(rows) if !rows.is_empty() => {
            return (
                StatusCode::CONFLICT,
                format!("a bundle named '{to}' already exists"),
            )
                .into_response()
        }
        Ok(_) => {}
        Err(e) => return internal(e),
    }
    let versions = match bundles.list_by_name(who.tenant_id, &from).await {
        Ok(rows) if rows.is_empty() => {
            return (StatusCode::NOT_FOUND, "bundle not found").into_response()
        }
        Ok(rows) => rows,
        Err(e) => return internal(e),
    };

    // Exactly the encrypted versions, each with a staged file.
    let encrypted: Vec<&fleet_storage::BundleRow> = versions
        .iter()
        .filter(|b| b.format != encbundle::FORMAT_PLAIN)
        .collect();
    if let Some(id) = body
        .resealed
        .keys()
        .find(|id| !encrypted.iter().any(|b| &b.id == *id))
    {
        return (
            StatusCode::BAD_REQUEST,
            format!("'{id}' is not an encrypted version of '{from}'"),
        )
            .into_response();
    }
    if let Some(missing) = encrypted
        .iter()
        .find(|b| !body.resealed.contains_key(&b.id))
    {
        return (
            StatusCode::BAD_REQUEST,
            format!(
                "version {} is encrypted: re-seal it under the new name in the browser",
                missing.version
            ),
        )
            .into_response();
    }

    let signing_key = match load_tenant_signing_key(&state, who.tenant_id).await {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "bundle signing key unavailable");
            return (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response();
        }
    };
    let sign = |id: &str, version: &fleet_storage::BundleRow, sha256: &str| {
        sign_descriptor(
            &signing_key,
            &fleet_core::crypto::bundlesig::BundleDescriptor {
                tenant_id: who.tenant_id,
                bundle_id: id,
                name: &to,
                version: &version.version,
                format: &version.format,
                sha256_hex: sha256,
            },
        )
    };

    let mut moved = Vec::new();
    for version in &encrypted {
        let staged = &body.resealed[&version.id];
        // A staged id names a file, so it must be one we could have minted, and one no
        // bundle row already owns.
        let owned = match bundles.get(who.tenant_id, staged).await {
            Ok(row) => row.is_some(),
            Err(e) => return internal(e),
        };
        if !valid_bundle_id(staged) || owned {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "version {}: '{staged}' is not a staged re-seal",
                    version.version
                ),
            )
                .into_response();
        }
        let bytes = match state.bundle_store.get(who.tenant_id, staged).await {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!(
                        "version {}: the staged re-seal is gone — re-seal it again",
                        version.version
                    ),
                )
                    .into_response()
            }
        };
        let fingerprint = match check_resealed(version, &bytes) {
            Ok(f) => f,
            Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
        };
        let sha = sha256_hex(&bytes);
        moved.push(MovedBundle {
            old_id: version.id.clone(),
            new_id: staged.clone(),
            signature: sign(staged, version, &sha),
            sha256: sha,
            size_bytes: bytes.len() as i64,
            key_fingerprint: Some(fingerprint),
        });
    }
    let in_place: Vec<RenamedInPlace> = versions
        .iter()
        .filter(|b| b.format == encbundle::FORMAT_PLAIN)
        .map(|b| RenamedInPlace {
            id: b.id.clone(),
            signature: sign(&b.id, b, &b.sha256),
        })
        .collect();

    match bundles
        .rename(who.tenant_id, &from, &to, &in_place, &moved)
        .await
    {
        Ok(RenameOutcome::Renamed) => {}
        Ok(RenameOutcome::NameTaken) => {
            return (
                StatusCode::CONFLICT,
                format!("a bundle named '{to}' already exists"),
            )
                .into_response()
        }
        Ok(RenameOutcome::Changed) => {
            return (
                StatusCode::CONFLICT,
                "the bundle changed while it was being renamed — reload and try again",
            )
                .into_response()
        }
        Err(e) => return internal(e),
    }

    // One entry per version, under the id it has now, saying which it had: earlier entries
    // — uploads and assignments — are recorded by id, and this is what links them.
    for b in &versions {
        let new_id = moved
            .iter()
            .find(|m| m.old_id == b.id)
            .map_or(b.id.as_str(), |m| m.new_id.as_str());
        crate::admin::audit::record(
            &state,
            who.tenant_id,
            Some(who.user_id),
            "bundle.renamed",
            "bundle",
            new_id,
            Some(&serde_json::json!({
                "from": from, "to": to, "version": b.version, "old_id": b.id,
            })),
        )
        .await;
    }

    match bundles.list_by_name(who.tenant_id, &to).await {
        Ok(rows) => {
            Json(rows.into_iter().map(BundleView::from).collect::<Vec<_>>()).into_response()
        }
        Err(_) => StatusCode::NO_CONTENT.into_response(),
    }
}
