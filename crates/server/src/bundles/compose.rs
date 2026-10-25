use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fleet_core::crypto::encbundle;
use fleet_storage::BundlesRepo;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::archive::{
    build_zip, manifest_toml, path_clash, read_zip_entries, template_from_manifest,
    valid_script_path, MAX_SCRIPT_FILES,
};
use super::upload::persist_bundle;
use super::valid_bundle_token;
use crate::auth::AuthedUser;
use crate::AppState;

#[derive(Deserialize)]
pub struct ComposeBody {
    pub name: String,
    pub version: String,
    /// The bundle's JSON Merge Patch fragment (what lands in config.json).
    pub config_json: serde_json::Value,
    /// When set, every entry EXCEPT config.json / bundle.toml is copied from this
    /// existing bundle into the new one — so "edit config, save as next version"
    /// preserves the bundle's scripts untouched.
    #[serde(default)]
    pub base_bundle_id: Option<String>,
    /// Id of the UI template this bundle was created from (e.g. "windows-server-health").
    /// Recorded in bundle.toml so later edits can keep showing the association; agents
    /// ignore it.
    #[serde(default)]
    pub template: Option<String>,
    /// The bundle's complete set of `scripts/` entries, as written by the script editor.
    /// When present it replaces every `scripts/` entry the base carried (an empty list
    /// removes them all); when absent the base's scripts are carried over untouched.
    #[serde(default)]
    pub scripts: Option<Vec<ScriptFile>>,
}

/// One file under `scripts/`. Content is base64 so uploaded scripts round-trip byte for
/// byte — a UTF-16 PowerShell file or a CRLF batch file is not the editor's to normalise.
#[derive(Deserialize)]
pub struct ScriptFile {
    pub path: String,
    pub content_b64: String,
}

/// `POST /api/bundles/compose` — build a bundle server-side from an edited config.
/// Backs the UI's INI editor: the client converts INI ↔ JSON; the server owns the zip
/// format and signing so no zip tooling is needed in the browser.
pub async fn compose(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<ComposeBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if let Some(refused) = crate::config_source::refuse_if_managed(&state, who.tenant_id) {
        return refused;
    }
    let name = body.name.trim();
    let version = body.version.trim();
    if !valid_bundle_token(name) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid name (allowed: alphanumerics, dot, dash, underscore)",
        )
            .into_response();
    }
    if !valid_bundle_token(version) {
        return (
            StatusCode::BAD_REQUEST,
            "invalid version (allowed: alphanumerics, dot, dash, underscore)",
        )
            .into_response();
    }
    if !body.config_json.is_object() {
        return (StatusCode::BAD_REQUEST, "config_json must be a JSON object").into_response();
    }
    let template = body
        .template
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    if let Some(t) = template {
        if !valid_bundle_token(t) {
            return (
                StatusCode::BAD_REQUEST,
                "invalid template (allowed: alphanumerics, dot, dash, underscore)",
            )
                .into_response();
        }
    }

    // Entries carried over from the base bundle (scripts and any other assets).
    let mut carried: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(base_id) = body.base_bundle_id.as_deref() {
        match BundlesRepo::new(&state.db)
            .get(who.tenant_id, base_id)
            .await
            .ok()
            .flatten()
        {
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    "the bundle you were editing is gone (renamed or deleted) — reopen it",
                )
                    .into_response()
            }
            Some(base) if base.name != name => {
                return (
                    StatusCode::CONFLICT,
                    format!(
                        "the bundle you were editing has been renamed to '{}' — reopen it",
                        base.name
                    ),
                )
                    .into_response();
            }
            Some(base) if base.format != encbundle::FORMAT_PLAIN => {
                return (
                    StatusCode::CONFLICT,
                    "base bundle is encrypted — the server cannot read it; edit and re-encrypt client-side",
                )
                    .into_response();
            }
            Some(_) => {}
        }
        let base_bytes = match state.bundle_store.get(who.tenant_id, base_id).await {
            Ok(b) => b,
            Err(e) => {
                tracing::error!(error = %e, "base bundle bytes missing");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "base bundle bytes missing",
                )
                    .into_response();
            }
        };
        match read_zip_entries(&base_bytes) {
            Ok(entries) => {
                carried = entries
                    .into_iter()
                    .filter(|(n, _)| n != "config.json" && n != "bundle.toml")
                    .collect();
            }
            Err(e) => {
                return (
                    StatusCode::CONFLICT,
                    format!("base bundle is not a readable zip: {e}"),
                )
                    .into_response();
            }
        }
    }

    if let Some(scripts) = body.scripts {
        // Paths the base already shipped are kept even when they fall outside what the
        // editor creates: an uploaded zip never had that rule, and the editor cannot rename.
        let grandfathered: HashSet<String> = carried
            .iter()
            .map(|(n, _)| n.clone())
            .filter(|n| n.starts_with("scripts/"))
            .collect();
        if scripts.len() > MAX_SCRIPT_FILES.max(grandfathered.len()) {
            return (
                StatusCode::BAD_REQUEST,
                format!("too many script files (limit {MAX_SCRIPT_FILES})"),
            )
                .into_response();
        }
        let new_paths: Vec<&str> = scripts
            .iter()
            .map(|s| s.path.as_str())
            .filter(|p| !grandfathered.contains(*p))
            .collect();
        if let Some(bad) = new_paths.iter().find(|p| !valid_script_path(p)) {
            return (
                StatusCode::BAD_REQUEST,
                format!(
                    "invalid script path {bad:?} (scripts/ followed by letters, digits, \
                     '.', '_', '-' and '/')"
                ),
            )
                .into_response();
        }
        let all: Vec<&str> = scripts.iter().map(|s| s.path.as_str()).collect();
        for path in &new_paths {
            if let Some(other) = path_clash(path, &all) {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("script path {path:?} clashes with {other:?}"),
                )
                    .into_response();
            }
        }
        let mut seen = HashSet::new();
        let mut decoded = Vec::with_capacity(scripts.len());
        for script in scripts {
            if !seen.insert(script.path.clone()) {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("duplicate script path {:?}", script.path),
                )
                    .into_response();
            }
            let Ok(data) = STANDARD.decode(script.content_b64.as_bytes()) else {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("script {:?} is not valid base64", script.path),
                )
                    .into_response();
            };
            decoded.push((script.path, data));
        }
        carried.retain(|(n, _)| !n.starts_with("scripts/"));
        carried.extend(decoded);
    }

    let config_pretty =
        serde_json::to_string_pretty(&body.config_json).unwrap_or_else(|_| "{}".to_string());
    let manifest = manifest_toml(name, version, template);

    let bytes = match build_zip(&manifest, &config_pretty, &carried) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "bundle zip build failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "zip build failed").into_response();
        }
    };

    match persist_bundle(
        &state,
        &who,
        name,
        version,
        bytes,
        encbundle::FORMAT_PLAIN,
        None,
        "bundle.composed",
    )
    .await
    {
        Ok(view) => (StatusCode::CREATED, Json(view)).into_response(),
        Err(resp) => resp,
    }
}

#[derive(Serialize)]
pub struct BundleConfigView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub config_json: serde_json::Value,
    /// Script entries present in the zip (paths under scripts/). The editor fetches their
    /// contents from the bundle download when there are any.
    pub scripts: Vec<String>,
    /// Template id recorded in bundle.toml when the bundle was created from a UI
    /// template; null for blank/uploaded bundles.
    pub template: Option<String>,
}

/// `GET /api/bundles/:id/config` — extract config.json (and the script listing) from a
/// stored bundle so the UI can edit it.
pub async fn get_config(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(bundle_id): Path<String>,
) -> Response {
    let row = match BundlesRepo::new(&state.db)
        .get(who.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "bundle not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundle get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if row.format != encbundle::FORMAT_PLAIN {
        return (
            StatusCode::CONFLICT,
            "bundle is encrypted — the server cannot read its contents",
        )
            .into_response();
    }
    let bytes = match state.bundle_store.get(who.tenant_id, &bundle_id).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "bundle bytes missing");
            return (StatusCode::NOT_FOUND, "bundle bytes missing").into_response();
        }
    };
    let entries = match read_zip_entries(&bytes) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                format!("bundle is not a readable zip: {e}"),
            )
                .into_response();
        }
    };

    let mut config_json = serde_json::json!({});
    let mut scripts = Vec::new();
    let mut template = None;
    for (entry_name, data) in &entries {
        if entry_name == "bundle.toml" {
            template = template_from_manifest(data);
        } else if entry_name == "config.json" {
            match serde_json::from_slice(data) {
                Ok(v) => config_json = v,
                Err(e) => {
                    return (
                        StatusCode::CONFLICT,
                        format!("bundle config.json is invalid JSON: {e}"),
                    )
                        .into_response();
                }
            }
        } else if entry_name.starts_with("scripts/") && !entry_name.ends_with('/') {
            scripts.push(entry_name.clone());
        }
    }
    scripts.sort();

    Json(BundleConfigView {
        id: row.id,
        name: row.name,
        version: row.version,
        config_json,
        scripts,
        template,
    })
    .into_response()
}
