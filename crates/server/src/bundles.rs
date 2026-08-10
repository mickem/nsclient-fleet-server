//! Bundle upload, signing, assignment to groups, and mTLS delivery (Phase 5c).

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use axum::{
    body::Body,
    extract::{Multipart, Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::pkcs8::DecodePrivateKey;
use ed25519_dalek::{Signer, SigningKey};
use fleet_storage::{
    BundleAssignmentsRepo, BundlesRepo, GroupsRepo, TenantRepo, TenantSecretsRepo,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::auth::AuthedUser;
use crate::mtls::PeerHostContext;
use crate::AppState;

#[async_trait]
pub trait BundleStore: Send + Sync {
    async fn put(&self, tenant_id: i64, bundle_id: &str, bytes: &[u8]) -> Result<()>;
    async fn get(&self, tenant_id: i64, bundle_id: &str) -> Result<Vec<u8>>;
    #[allow(dead_code)]
    async fn delete(&self, tenant_id: i64, bundle_id: &str) -> Result<()>;
}

#[derive(Clone)]
pub struct LocalBundleStore {
    base: Arc<PathBuf>,
}

impl LocalBundleStore {
    pub fn new(base: impl Into<PathBuf>) -> Self {
        Self {
            base: Arc::new(base.into()),
        }
    }

    fn path_for(&self, tenant_id: i64, bundle_id: &str) -> PathBuf {
        self.base
            .join(tenant_id.to_string())
            .join(format!("{bundle_id}.zip"))
    }
}

#[async_trait]
impl BundleStore for LocalBundleStore {
    async fn put(&self, tenant_id: i64, bundle_id: &str, bytes: &[u8]) -> Result<()> {
        let path = self.path_for(tenant_id, bundle_id);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, bytes).await?;
        Ok(())
    }

    async fn get(&self, tenant_id: i64, bundle_id: &str) -> Result<Vec<u8>> {
        let path = self.path_for(tenant_id, bundle_id);
        Ok(tokio::fs::read(&path).await?)
    }

    async fn delete(&self, tenant_id: i64, bundle_id: &str) -> Result<()> {
        let path = self.path_for(tenant_id, bundle_id);
        tokio::fs::remove_file(&path).await?;
        Ok(())
    }
}

#[derive(Serialize)]
pub struct BundleView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub size_bytes: i64,
    pub signature: String,
    pub uploaded_at: i64,
}

/// `POST /api/bundles` — multipart upload. Required parts:
///   - `name` (text)
///   - `version` (text)
///   - `bundle` (file: zip OR raw bytes; we don't unpack — opaque blob from server's view)
pub async fn upload(
    State(state): State<AppState>,
    who: AuthedUser,
    mut form: Multipart,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let mut name: Option<String> = None;
    let mut version: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = form.next_field().await {
        match field.name().unwrap_or("").to_string().as_str() {
            "name" => name = field.text().await.ok(),
            "version" => version = field.text().await.ok(),
            "bundle" => {
                bytes = field.bytes().await.ok().map(|b| b.to_vec());
            }
            _ => {}
        }
    }

    let name = match name.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(n) => n.to_string(),
        None => return (StatusCode::BAD_REQUEST, "missing name").into_response(),
    };
    let version = match version.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(v) => v.to_string(),
        None => return (StatusCode::BAD_REQUEST, "missing version").into_response(),
    };
    let bytes = match bytes {
        Some(b) if !b.is_empty() => b,
        _ => return (StatusCode::BAD_REQUEST, "missing or empty bundle").into_response(),
    };

    match persist_bundle(&state, &who, &name, &version, bytes, "bundle.uploaded").await {
        Ok(view) => Json(view).into_response(),
        Err(resp) => resp,
    }
}

/// Shared tail of every bundle-creating path: tier size check, sign with the tenant key,
/// insert the row, store the bytes, bump config_version, audit. Returns the error as a
/// ready-to-send Response so handlers stay thin.
async fn persist_bundle(
    state: &AppState,
    who: &AuthedUser,
    name: &str,
    version: &str,
    bytes: Vec<u8>,
    audit_action: &str,
) -> std::result::Result<BundleView, Response> {
    let tenant = match TenantRepo::new(&state.db).get(who.tenant_id).await {
        Ok(Some(t)) => t,
        _ => return Err((StatusCode::INTERNAL_SERVER_ERROR, "tenant missing").into_response()),
    };
    let limits = fleet_core::tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());
    let max = (limits.max_bundle_mb as usize) * 1024 * 1024;
    if bytes.len() > max {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("bundle exceeds tier limit ({} MB)", limits.max_bundle_mb),
        )
            .into_response());
    }

    let sha = sha256_hex(&bytes);
    let signature_b64 = match sign_with_tenant_key(state, who.tenant_id, &bytes).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "bundle sign failed");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response());
        }
    };

    let bundles = BundlesRepo::new(&state.db);
    let row = match bundles
        .create(
            who.tenant_id,
            name,
            version,
            &sha,
            bytes.len() as i64,
            &signature_b64,
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

    crate::audit::record(
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
        })),
    )
    .await;

    Ok(BundleView {
        id: row.id,
        name: row.name,
        version: row.version,
        sha256: row.sha256,
        size_bytes: row.size_bytes,
        signature: row.signature,
        uploaded_at: row.uploaded_at,
    })
}

fn valid_bundle_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

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

    // Entries carried over from the base bundle (scripts and any other assets).
    let mut carried: Vec<(String, Vec<u8>)> = Vec::new();
    if let Some(base_id) = body.base_bundle_id.as_deref() {
        if BundlesRepo::new(&state.db)
            .get(who.tenant_id, base_id)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            return (StatusCode::NOT_FOUND, "base bundle not found").into_response();
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

    let config_pretty =
        serde_json::to_string_pretty(&body.config_json).unwrap_or_else(|_| "{}".to_string());
    let manifest = format!("name = \"{name}\"\nversion = \"{version}\"\nschema_version = 1\n");

    let bytes = match build_zip(&manifest, &config_pretty, &carried) {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "bundle zip build failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "zip build failed").into_response();
        }
    };

    match persist_bundle(&state, &who, name, version, bytes, "bundle.composed").await {
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
    /// Script entries present in the zip (paths under scripts/). Read-only for now —
    /// the editor preserves them via compose's base_bundle_id.
    pub scripts: Vec<String>,
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
    for (entry_name, data) in &entries {
        if entry_name == "config.json" {
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
    })
    .into_response()
}

fn build_zip(
    manifest_toml: &str,
    config_json: &str,
    carried: &[(String, Vec<u8>)],
) -> Result<Vec<u8>> {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut writer = zip::ZipWriter::new(&mut cursor);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        writer.start_file("bundle.toml", opts)?;
        writer.write_all(manifest_toml.as_bytes())?;
        writer.start_file("config.json", opts)?;
        writer.write_all(config_json.as_bytes())?;
        for (name, data) in carried {
            writer.start_file(name, opts)?;
            writer.write_all(data)?;
        }
        writer.finish()?;
    }
    Ok(cursor.into_inner())
}

fn read_zip_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    let mut out = Vec::with_capacity(archive.len());
    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }
        let mut name = file.name().replace('\\', "/");
        if let Some(stripped) = name.strip_prefix("./") {
            name = stripped.to_string();
        }
        let mut data = Vec::with_capacity(file.size() as usize);
        file.read_to_end(&mut data)?;
        out.push((name, data));
    }
    Ok(out)
}

pub async fn list(State(state): State<AppState>, who: AuthedUser) -> Response {
    let bundles = BundlesRepo::new(&state.db);
    match bundles.list(who.tenant_id).await {
        Ok(rows) => Json(
            rows.into_iter()
                .map(|b| BundleView {
                    id: b.id,
                    name: b.name,
                    version: b.version,
                    sha256: b.sha256,
                    size_bytes: b.size_bytes,
                    signature: b.signature,
                    uploaded_at: b.uploaded_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundles list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct AssignBody {
    pub bundle_id: String,
    #[serde(default = "default_priority")]
    pub priority: i64,
}

fn default_priority() -> i64 {
    100
}

pub async fn assign_to_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(group_id): Path<String>,
    Json(body): Json<AssignBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    if GroupsRepo::new(&state.db)
        .get(who.tenant_id, &group_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    }
    if BundlesRepo::new(&state.db)
        .get(who.tenant_id, &body.bundle_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "bundle not found").into_response();
    }

    if let Err(e) = BundleAssignmentsRepo::new(&state.db)
        .assign(who.tenant_id, &group_id, &body.bundle_id, body.priority)
        .await
    {
        tracing::error!(error = %e, "assign failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    }
    if let Err(e) = TenantRepo::new(&state.db)
        .bump_config_version(who.tenant_id)
        .await
    {
        tracing::error!(error = %e, "config_version bump failed");
    }
    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "bundle.assigned",
        "group",
        &group_id,
        Some(&serde_json::json!({
            "bundle_id": body.bundle_id,
            "priority": body.priority,
        })),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

#[derive(Serialize)]
pub struct AssignmentView {
    pub bundle_id: String,
    pub name: String,
    pub version: String,
    pub priority: i64,
}

/// `GET /api/groups/:id/bundles` — the bundles assigned to one group, with priorities.
pub async fn list_for_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(group_id): Path<String>,
) -> Response {
    if GroupsRepo::new(&state.db)
        .get(who.tenant_id, &group_id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        return (StatusCode::NOT_FOUND, "group not found").into_response();
    }
    match BundleAssignmentsRepo::new(&state.db)
        .list_for_groups(who.tenant_id, &[group_id])
        .await
    {
        Ok(rows) => {
            let mut views: Vec<AssignmentView> = rows
                .into_iter()
                .map(|(b, priority)| AssignmentView {
                    bundle_id: b.id,
                    name: b.name,
                    version: b.version,
                    priority,
                })
                .collect();
            views.sort_by_key(|v| v.priority);
            Json(views).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "assignment list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `DELETE /api/groups/:id/bundles/:bundle_id` — remove an assignment.
pub async fn unassign_from_group(
    State(state): State<AppState>,
    who: AuthedUser,
    Path((group_id, bundle_id)): Path<(String, String)>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    match BundleAssignmentsRepo::new(&state.db)
        .unassign(who.tenant_id, &group_id, &bundle_id)
        .await
    {
        Ok(true) => {
            if let Err(e) = TenantRepo::new(&state.db)
                .bump_config_version(who.tenant_id)
                .await
            {
                tracing::error!(error = %e, "config_version bump failed");
            }
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "bundle.unassigned",
                "group",
                &group_id,
                Some(&serde_json::json!({ "bundle_id": bundle_id })),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "assignment not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "unassign failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `GET /agent/v1/bundles/:id` — mTLS download. Authorization: the host's effective bundle set
/// must include this bundle (i.e., the host's tags match a group that has this bundle assigned).
pub async fn download(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    Path(bundle_id): Path<String>,
) -> Response {
    use crate::desired_state::compute_desired_state;
    let ds = match compute_desired_state(&state, ctx.tenant_id, &ctx.host_id).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "compute_desired_state failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if !ds.bundles.iter().any(|b| b.id == bundle_id) {
        return (StatusCode::FORBIDDEN, "bundle not assigned to this host").into_response();
    }

    match state.bundle_store.get(ctx.tenant_id, &bundle_id).await {
        Ok(bytes) => {
            let mut resp = Response::new(Body::from(bytes));
            resp.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/zip"),
            );
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, %bundle_id, "bundle store get failed");
            (StatusCode::NOT_FOUND, "bundle bytes missing").into_response()
        }
    }
}

async fn sign_with_tenant_key(state: &AppState, tenant_id: i64, payload: &[u8]) -> Result<String> {
    let secrets = TenantSecretsRepo::new(&state.db)
        .get_by_tenant(tenant_id)
        .await?
        .ok_or_else(|| anyhow!("tenant secrets missing for {tenant_id}"))?;
    let key_bytes = state
        .config
        .master_key
        .decrypt(&secrets.bundle_signing_key_encrypted)?;
    let key_pem = std::str::from_utf8(&key_bytes).context("bundle key utf8")?;
    let signing_key =
        SigningKey::from_pkcs8_pem(key_pem).map_err(|e| anyhow!("ed25519 key parse: {e}"))?;
    // Sign sha256(payload). The agent verifies sig over the same digest.
    let digest = Sha256::digest(payload);
    let signature = signing_key.sign(&digest);
    Ok(STANDARD.encode(signature.to_bytes()))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let d = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in d.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
