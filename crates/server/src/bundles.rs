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
use fleet_core::digest::sha256_hex;
use fleet_core::encbundle;
use fleet_storage::{
    BundleAssignmentsRepo, BundlesRepo, GroupsRepo, MovedBundle, RenameOutcome, RenamedInPlace,
    TenantBundleKeysRepo, TenantRepo, TenantSecretsRepo,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::auth::AuthedUser;
use crate::mtls::PeerHostContext;
use crate::AppState;

#[async_trait]
pub trait BundleStore: Send + Sync {
    async fn put(&self, tenant_id: i64, bundle_id: &str, bytes: &[u8]) -> Result<()>;
    async fn get(&self, tenant_id: i64, bundle_id: &str) -> Result<Vec<u8>>;
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
    /// `plain` or `enc-v1`. Encrypted bundles are client-side AES-256-GCM envelopes the
    /// server cannot read or edit — see `fleet_core::encbundle`.
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

/// `POST /api/bundles` — multipart upload. Required parts:
///   - `name` (text)
///   - `version` (text)
///   - `bundle` (file: zip OR raw bytes; we don't unpack — opaque blob from server's view)
///
/// Optional:
///   - `format` (text): `plain` (default) or `enc-v1` for a client-side encrypted NSEB1
///     envelope. Encrypted uploads are validated structurally (magic + header) and their
///     key fingerprint recorded; the server can neither read nor produce their contents.
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
    let mut format: Option<String> = None;
    let mut bytes: Option<Vec<u8>> = None;

    while let Ok(Some(field)) = form.next_field().await {
        match field.name().unwrap_or("").to_string().as_str() {
            "name" => name = field.text().await.ok(),
            "version" => version = field.text().await.ok(),
            "format" => format = field.text().await.ok(),
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
async fn persist_bundle(
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
    // see `fleet_core::bundlesig` for why a signature over the digest alone was worth so
    // little.
    let bundle_id = fleet_core::bundlesig::new_bundle_id();
    let descriptor = fleet_core::bundlesig::BundleDescriptor {
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
            "format": row.format,
        })),
    )
    .await;

    Ok(row.into())
}

/// Shared refusal text, so upload and compose say the same thing.
const BUNDLE_TOKEN_RULE: &str =
    "name and version must be 1-128 characters of letters, digits, '.', '_' or '-'";

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
    /// Id of the UI template this bundle was created from (e.g. "windows-server-health").
    /// Recorded in bundle.toml so later edits can keep showing the association; agents
    /// ignore it.
    #[serde(default)]
    pub template: Option<String>,
}

/// The bundle.toml the compose paths (server here, browser in web/src/bundlezip.ts) write.
/// All values are token-validated before this is called, so the quoting cannot be broken.
fn manifest_toml(name: &str, version: &str, template: Option<&str>) -> String {
    let mut m = format!("name = \"{name}\"\nversion = \"{version}\"\nschema_version = 1\n");
    if let Some(t) = template {
        m.push_str(&format!("template = \"{t}\"\n"));
    }
    m
}

/// Pull the `template = "<token>"` line back out of a stored bundle's manifest. The
/// manifest is machine-written, so a line parse suffices; token validation keeps anything
/// odd from a hand-built zip out of the API.
fn template_from_manifest(bytes: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("template")?.trim_start();
        let value = rest.strip_prefix('=')?.trim();
        let value = value.strip_prefix('"')?.strip_suffix('"')?;
        valid_bundle_token(value).then(|| value.to_string())
    })
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
            None => return (StatusCode::NOT_FOUND, "base bundle not found").into_response(),
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
    /// Script entries present in the zip (paths under scripts/). Read-only for now —
    /// the editor preserves them via compose's base_bundle_id.
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

/// Most a bundle may expand to across all its entries.
///
/// Bundles carry configuration, scripts and small assets; the largest tier allows a 250 MB
/// upload, and nothing legitimate inflates far past that. The cap is on the *total*, so a
/// thousand small entries cannot add up to the same attack a single large one would.
const MAX_INFLATED_TOTAL: u64 = 512 * 1024 * 1024;

/// Most entries we will walk. A zip can declare millions of them in a few kilobytes.
const MAX_ZIP_ENTRIES: usize = 10_000;

/// Read a bundle zip into memory, refusing anything that would cost more than it should.
///
/// Three separate limits, because a zip's header is written by whoever made the file and
/// none of it is evidence of anything:
///
/// - the output buffer is never pre-sized from the declared size. `Vec::with_capacity` on
///   an attacker-chosen `u64` is an allocation failure, and an allocation failure aborts
///   the process — so a crafted header was a remote kill, reachable through the config-read
///   endpoint by any tenant session.
/// - inflation is read through `take`, against a budget shared by every entry, so the
///   compression ratio cannot turn a 2 MiB upload into gigabytes of resident memory.
/// - entry names must stay inside the archive. The server never extracts, so traversal is
///   an agent-side risk rather than ours, but propagating `../../etc/…` from a hand-crafted
///   upload into a composed bundle we sign makes it our problem.
///
/// Upload does not parse, so a crafted file is stored first and opened later by whoever
/// reads the config — which is why this is a refusal and not a panic.
fn read_zip_entries(bytes: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    read_zip_entries_within(bytes, MAX_INFLATED_TOTAL)
}

/// As [`read_zip_entries`], with the budget spelled out so tests can exercise the refusal
/// without actually inflating half a gigabyte.
fn read_zip_entries_within(bytes: &[u8], mut budget: u64) -> Result<Vec<(String, Vec<u8>)>> {
    use std::io::Read;
    let mut archive = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;
    if archive.len() > MAX_ZIP_ENTRIES {
        anyhow::bail!(
            "bundle declares {} entries (limit {MAX_ZIP_ENTRIES})",
            archive.len()
        );
    }

    let mut out = Vec::with_capacity(archive.len().min(1024));
    for i in 0..archive.len() {
        let file = archive.by_index(i)?;
        if file.is_dir() {
            continue;
        }

        // `enclosed_name` is the library's own answer to "is this name safe to join onto a
        // directory": it rejects absolute paths, parent components and Windows drive
        // prefixes. Taking it before normalising means we never have to decide which of
        // those our own normalisation happened to cover.
        let Some(safe) = file.enclosed_name() else {
            anyhow::bail!("bundle entry {:?} escapes the archive", file.name());
        };
        let name = safe
            .components()
            .map(|c| c.as_os_str().to_string_lossy())
            .collect::<Vec<_>>()
            .join("/");
        if name.is_empty() {
            continue;
        }

        // Read against the shared budget, one byte past it so overrun is detectable rather
        // than a silent truncation that we would then sign.
        let mut data = Vec::new();
        let read = file.take(budget + 1).read_to_end(&mut data)? as u64;
        if read > budget {
            anyhow::bail!("bundle expands past {} MiB", budget / (1024 * 1024));
        }
        budget -= read;
        out.push((name, data));
    }
    Ok(out)
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
    crate::config_api::bump_config_version(&state, who.tenant_id).await;

    crate::audit::record(
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

/// Best-effort removal of stored bytes no row points at (any more). `why` says which in
/// the log when a file cannot be removed.
async fn discard_bundle_bytes(state: &AppState, tenant_id: i64, ids: &[String], why: &str) {
    for id in ids {
        if let Err(e) = state.bundle_store.delete(tenant_id, id).await {
            tracing::error!(error = %e, bundle_id = %id, "{why}: bundle bytes not removed");
        }
    }
}

/// Multipart part name prefix of a re-sealed encrypted version: `sealed:<bundle id>`.
const SEALED_PART_PREFIX: &str = "sealed:";

/// Longest `from`/`to` part we read. Names are at most 128 bytes; anything longer is not a
/// name, and is not buffered to find that out.
const MAX_NAME_PART: usize = 1024;

/// Read a small text part, refusing one longer than `max` bytes without buffering it.
async fn read_small_text(
    field: &mut axum::extract::multipart::Field<'_>,
    max: usize,
) -> Option<String> {
    let mut buf = Vec::new();
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                if buf.len() + chunk.len() > max {
                    return None;
                }
                buf.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(_) => return None,
        }
    }
    String::from_utf8(buf).ok()
}

/// What a rename needs once it knows which bundle it is renaming.
struct RenamePlan {
    from: String,
    to: String,
    versions: Vec<fleet_storage::BundleRow>,
    signing_key: SigningKey,
}

// result_large_err: the Err is a ready-to-send Response by design, as in persist_bundle.
#[allow(clippy::result_large_err)]
async fn plan_rename(
    state: &AppState,
    who: &AuthedUser,
    from: Option<String>,
    to: Option<String>,
) -> std::result::Result<RenamePlan, Response> {
    // `from` is matched exactly as stored: a bundle uploaded before names were validated
    // is the one most worth renaming, and must not be refused for the name it has.
    let from = match from {
        Some(f) if !f.is_empty() => f,
        _ => return Err((StatusCode::BAD_REQUEST, "missing 'from'").into_response()),
    };
    let to = match to.as_deref().map(str::trim) {
        Some(t) if valid_bundle_token(t) => t.to_string(),
        _ => return Err((StatusCode::BAD_REQUEST, BUNDLE_TOKEN_RULE).into_response()),
    };
    if from == to {
        return Err((StatusCode::BAD_REQUEST, "the new name is the current name").into_response());
    }
    let bundles = BundlesRepo::new(&state.db);
    let internal = |e: anyhow::Error| {
        tracing::error!(error = %e, "bundle rename lookup failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
    };
    if !bundles
        .list_by_name(who.tenant_id, &to)
        .await
        .map_err(internal)?
        .is_empty()
    {
        return Err((
            StatusCode::CONFLICT,
            format!("a bundle named '{to}' already exists"),
        )
            .into_response());
    }
    let versions = bundles
        .list_by_name(who.tenant_id, &from)
        .await
        .map_err(internal)?;
    if versions.is_empty() {
        return Err((StatusCode::NOT_FOUND, "bundle not found").into_response());
    }
    let signing_key = load_tenant_signing_key(state, who.tenant_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "bundle signing key unavailable");
            (StatusCode::INTERNAL_SERVER_ERROR, "sign failed").into_response()
        })?;
    Ok(RenamePlan {
        from,
        to,
        versions,
        signing_key,
    })
}

/// Read one re-sealed version, check that it is, as far as the server can tell, the same
/// content sealed with the same key, store it under a new id, and describe the move.
// result_large_err: the Err is a ready-to-send Response by design.
#[allow(clippy::result_large_err)]
async fn take_sealed_part(
    state: &AppState,
    tenant_id: i64,
    plan: &RenamePlan,
    version: &fleet_storage::BundleRow,
    field: &mut axum::extract::multipart::Field<'_>,
) -> std::result::Result<MovedBundle, Response> {
    let bad = |msg: String| Err((StatusCode::BAD_REQUEST, msg).into_response());
    // AES-GCM output is exactly as long as its input, so a version re-sealed from the same
    // plaintext is exactly as long as the original. Bounding the read by that keeps memory
    // to one version at a time and needs no tier check: the original already passed one.
    let expected = usize::try_from(version.size_bytes).unwrap_or(0);
    let mut bytes = Vec::with_capacity(expected);
    loop {
        match field.chunk().await {
            Ok(Some(chunk)) => {
                if bytes.len() + chunk.len() > expected {
                    return bad(format!(
                        "version {}: the re-sealed bundle is larger than the original",
                        version.version
                    ));
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok(None) => break,
            Err(e) => return bad(format!("version {}: unreadable part: {e}", version.version)),
        }
    }
    if bytes.len() != expected {
        return bad(format!(
            "version {}: the re-sealed bundle is not the same size as the original",
            version.version
        ));
    }
    let fingerprint = match encbundle::parse_header(&bytes) {
        Ok(h) => h.fingerprint_hex(),
        Err(e) => {
            return bad(format!(
                "version {}: not a valid encrypted bundle: {e}",
                version.version
            ))
        }
    };
    // A rename never changes which key opens a bundle: agents provisioned with the old one
    // would stop opening it, and the old ciphertext is about to be deleted.
    if version.key_fingerprint.as_deref() != Some(fingerprint.as_str()) {
        return bad(format!(
            "version {} is sealed with key {}; it must be re-sealed with the same key",
            version.version,
            version.key_fingerprint.as_deref().unwrap_or("?")
        ));
    }
    let new_id = fleet_core::bundlesig::new_bundle_id();
    let sha = sha256_hex(&bytes);
    let signature = sign_descriptor(
        &plan.signing_key,
        &fleet_core::bundlesig::BundleDescriptor {
            tenant_id,
            bundle_id: &new_id,
            name: &plan.to,
            version: &version.version,
            format: &version.format,
            sha256_hex: &sha,
        },
    );
    if let Err(e) = state.bundle_store.put(tenant_id, &new_id, &bytes).await {
        tracing::error!(error = %e, "bundle store put failed");
        return Err((StatusCode::INTERNAL_SERVER_ERROR, "store failed").into_response());
    }
    Ok(MovedBundle {
        old_id: version.id.clone(),
        new_id,
        sha256: sha,
        size_bytes: bytes.len() as i64,
        signature,
        key_fingerprint: Some(fingerprint),
    })
}

/// `POST /api/bundles/rename` — rename every version of a bundle. Multipart parts, in order:
///   - `from`, `to` (text): the current name, exactly as stored, and the new one.
///   - `sealed:<id>` (file), one per encrypted version of `from`: that version's plaintext
///     re-encrypted under (`to`, its version), with the same key. The AAD binds the name,
///     so an encrypted version renamed without new ciphertext would no longer open on any
///     agent — and only the browser holds the key to produce it.
///
/// Plain versions are renamed in place: same id, same bytes, re-signed over the sha256 the
/// row recorded at upload. The bytes are never read, so whatever is on disk is never
/// vouched for anew — a file changed since upload still fails the agent's digest check.
/// The zip's bundle.toml keeps the name it was built with; agents never read it, and the
/// next edit rewrites it. Encrypted versions move to new ids with their group assignments.
/// Either way every group carries the same versions as before, and every host carrying the
/// bundle gets a new desired-state hash (it covers the whole signed descriptor).
///
/// Sealed parts are streamed: each is checked and stored as it arrives, so a rename holds
/// one version in memory at a time. All or nothing: a rename that would leave some versions
/// behind is refused, and anything stored for it is removed again.
pub async fn rename(
    State(state): State<AppState>,
    who: AuthedUser,
    mut form: Multipart,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let mut from: Option<String> = None;
    let mut to: Option<String> = None;
    let mut plan: Option<RenamePlan> = None;
    let mut moved: Vec<MovedBundle> = Vec::new();
    // Every early return from here on has to take back what was stored for this rename.
    macro_rules! fail {
        ($resp:expr) => {{
            let written: Vec<String> = moved.iter().map(|m| m.new_id.clone()).collect();
            discard_bundle_bytes(&state, who.tenant_id, &written, "abandoned rename").await;
            return $resp;
        }};
    }

    loop {
        let mut field = match form.next_field().await {
            Ok(Some(f)) => f,
            Ok(None) => break,
            Err(e) => fail!((StatusCode::BAD_REQUEST, format!("bad form: {e}")).into_response()),
        };
        let part = field.name().unwrap_or("").to_string();
        if part == "from" || part == "to" {
            if plan.is_some() {
                fail!((
                    StatusCode::BAD_REQUEST,
                    "'from' and 'to' must come before sealed parts"
                )
                    .into_response());
            }
            let Some(text) = read_small_text(&mut field, MAX_NAME_PART).await else {
                return (StatusCode::BAD_REQUEST, "name part too long or not UTF-8")
                    .into_response();
            };
            if part == "from" {
                from = Some(text);
            } else {
                to = Some(text);
            }
        } else if let Some(id) = part.strip_prefix(SEALED_PART_PREFIX) {
            if plan.is_none() {
                match plan_rename(&state, &who, from.take(), to.take()).await {
                    Ok(p) => plan = Some(p),
                    Err(resp) => return resp,
                }
            }
            let p = plan.as_ref().expect("planned above");
            let Some(version) = p
                .versions
                .iter()
                .find(|b| b.id == id && b.format != encbundle::FORMAT_PLAIN)
            else {
                fail!((
                    StatusCode::BAD_REQUEST,
                    format!(
                        "sealed part for '{id}', which is not an encrypted version of '{}'",
                        p.from
                    ),
                )
                    .into_response());
            };
            if moved.iter().any(|m| m.old_id == version.id) {
                fail!((
                    StatusCode::BAD_REQUEST,
                    format!("version {} was sent twice", version.version)
                )
                    .into_response());
            }
            match take_sealed_part(&state, who.tenant_id, p, version, &mut field).await {
                Ok(m) => moved.push(m),
                Err(resp) => fail!(resp),
            }
        }
    }
    let plan = match plan {
        Some(p) => p,
        None => match plan_rename(&state, &who, from, to).await {
            Ok(p) => p,
            Err(resp) => return resp,
        },
    };

    // Every encrypted version needs new ciphertext.
    if let Some(missing) = plan
        .versions
        .iter()
        .find(|b| b.format != encbundle::FORMAT_PLAIN && !moved.iter().any(|m| m.old_id == b.id))
    {
        fail!((
            StatusCode::BAD_REQUEST,
            format!(
                "version {} is encrypted: re-seal it under the new name in the browser",
                missing.version
            ),
        )
            .into_response());
    }
    let in_place: Vec<RenamedInPlace> = plan
        .versions
        .iter()
        .filter(|b| b.format == encbundle::FORMAT_PLAIN)
        .map(|b| RenamedInPlace {
            id: b.id.clone(),
            signature: sign_descriptor(
                &plan.signing_key,
                &fleet_core::bundlesig::BundleDescriptor {
                    tenant_id: who.tenant_id,
                    bundle_id: &b.id,
                    name: &plan.to,
                    version: &b.version,
                    format: &b.format,
                    sha256_hex: &b.sha256,
                },
            ),
        })
        .collect();

    let bundles = BundlesRepo::new(&state.db);
    match bundles
        .rename(who.tenant_id, &plan.from, &plan.to, &in_place, &moved)
        .await
    {
        Ok(RenameOutcome::Renamed) => {}
        Ok(RenameOutcome::NameTaken) => fail!((
            StatusCode::CONFLICT,
            format!("a bundle named '{}' already exists", plan.to),
        )
            .into_response()),
        Ok(RenameOutcome::Changed) => fail!((
            StatusCode::CONFLICT,
            "the bundle changed while it was being renamed — reload and try again",
        )
            .into_response()),
        Err(e) => {
            tracing::error!(error = %e, "bundle rename failed");
            fail!((StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response())
        }
    }

    // The replaced ciphertext, after the commit (which bumped config_version, so nothing
    // serves the old ids any more): as for delete, an orphaned file is the direction to
    // fail in.
    let replaced: Vec<String> = moved.iter().map(|m| m.old_id.clone()).collect();
    discard_bundle_bytes(&state, who.tenant_id, &replaced, "renamed bundle").await;

    // Which id each version had and has, so earlier audit entries — uploads and assignments,
    // recorded by id — still lead to what the hosts run.
    let mut version_map: Vec<serde_json::Value> = plan
        .versions
        .iter()
        .map(|b| {
            let new_id = moved
                .iter()
                .find(|m| m.old_id == b.id)
                .map_or(b.id.as_str(), |m| m.new_id.as_str());
            serde_json::json!({
                "version": b.version, "format": b.format, "old_id": b.id, "new_id": new_id,
            })
        })
        .collect();
    version_map.sort_by(|a, b| a["version"].as_str().cmp(&b["version"].as_str()));
    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "bundle.renamed",
        "bundle",
        &plan.to,
        Some(&serde_json::json!({ "from": plan.from, "to": plan.to, "versions": version_map })),
    )
    .await;

    match bundles.list_by_name(who.tenant_id, &plan.to).await {
        Ok(rows) => {
            Json(rows.into_iter().map(BundleView::from).collect::<Vec<_>>()).into_response()
        }
        Err(_) => StatusCode::NO_CONTENT.into_response(),
    }
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
/// `GET /api/bundles/:id/download` — the stored bytes, exactly as uploaded, for the
/// operator's browser. Plain bundles come back as the signed zip; encrypted bundles as the
/// NSEB1 envelope, which the browser decrypts with the tenant key for client-side editing.
/// No role gate beyond a session: this returns nothing the server itself could read that
/// `GET /api/bundles/:id/config` does not already expose.
pub async fn ui_download(
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
            tracing::error!(error = %e, %bundle_id, "bundle store get failed");
            return (StatusCode::NOT_FOUND, "bundle bytes missing").into_response();
        }
    };
    let (content_type, ext) = if row.format == encbundle::FORMAT_ENC_V1 {
        ("application/octet-stream", "nseb")
    } else {
        ("application/zip", "zip")
    };
    // Uploaded names are only checked non-empty, so the filename is sanitized rather than
    // trusted into a header.
    let safe: String = format!("{}-{}", row.name, row.version)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{safe}.{ext}\"")) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

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
            let content_type = if encbundle::is_encrypted(&bytes) {
                "application/octet-stream"
            } else {
                "application/zip"
            };
            let mut resp = Response::new(Body::from(bytes));
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, %bundle_id, "bundle store get failed");
            (StatusCode::NOT_FOUND, "bundle bytes missing").into_response()
        }
    }
}

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
    crate::audit::record(
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
        fleet_core::aead::Purpose::TenantBundleSigningKey { tenant_id },
        &secrets.bundle_signing_key_encrypted,
    )?;
    let key_pem = std::str::from_utf8(&key_bytes).context("bundle key utf8")?;
    SigningKey::from_pkcs8_pem(key_pem).map_err(|e| anyhow!("ed25519 key parse: {e}"))
}

/// Sign a bundle's descriptor, base64.
///
/// The descriptor, not the bytes: a signature over the digest alone binds nothing about
/// *which* bundle those bytes are, so an old signed blob could be re-advertised under a new
/// name, version or id and still verify. See [`fleet_core::bundlesig`].
pub(crate) fn sign_descriptor(
    key: &SigningKey,
    descriptor: &fleet_core::bundlesig::BundleDescriptor<'_>,
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
    descriptor: &fleet_core::bundlesig::BundleDescriptor<'_>,
) -> Result<String> {
    Ok(sign_descriptor(
        &load_tenant_signing_key(state, tenant_id).await?,
        descriptor,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(entries: &[(&str, Vec<u8>)]) -> Vec<u8> {
        let mut cursor = std::io::Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut cursor);
            let opts = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated);
            for (name, data) in entries {
                w.start_file(*name, opts).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        cursor.into_inner()
    }

    #[test]
    fn inflation_is_capped_across_all_entries_together() {
        // Four megabytes of zeros deflate to a few kilobytes. A per-entry cap would let a
        // thousand of these add up to the same attack, so the budget is shared.
        let blob = zip_of(&[
            ("a.bin", vec![0u8; 4 * 1024 * 1024]),
            ("b.bin", vec![0u8; 4 * 1024 * 1024]),
        ]);
        assert!(blob.len() < 64 * 1024, "the crafted input is small");

        // Either entry fits on its own; together they do not.
        read_zip_entries_within(&blob, 6 * 1024 * 1024)
            .expect_err("two 4 MiB entries must not pass a 6 MiB budget");
        let ok = read_zip_entries_within(&blob, 16 * 1024 * 1024).expect("within budget");
        assert_eq!(ok.len(), 2);
    }

    #[test]
    fn a_declared_size_never_becomes_an_allocation() {
        // The output buffer used to be pre-sized from the zip header. A crafted entry
        // declaring a terabyte was therefore an allocation failure, and an allocation
        // failure aborts the process — a remote kill through the config-read endpoint.
        // We cannot assert "did not abort" directly, so assert the behaviour that replaced
        // it: the refusal is by bytes actually read, and it is an error, not a panic.
        let blob = zip_of(&[("pad.bin", vec![7u8; 1024 * 1024])]);
        let err = read_zip_entries_within(&blob, 1024).unwrap_err();
        assert!(
            err.to_string().contains("expands past"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn entries_that_escape_the_archive_are_refused() {
        for name in ["../../etc/cron.d/pwn", "/etc/shadow", "a/../../b"] {
            let blob = zip_of(&[(name, b"x".to_vec())]);
            let err = read_zip_entries_within(&blob, 1024 * 1024)
                .unwrap_err_or_ok_names()
                .unwrap_or_else(|| panic!("{name} should be refused"));
            assert!(err.contains("escapes the archive"), "{name}: {err}");
        }
    }

    /// Small helper so the loop above reads as "this must be refused" rather than as
    /// unwrapping in two directions.
    trait RefusalExt {
        fn unwrap_err_or_ok_names(self) -> Option<String>;
    }
    impl RefusalExt for Result<Vec<(String, Vec<u8>)>> {
        fn unwrap_err_or_ok_names(self) -> Option<String> {
            match self {
                Ok(_) => None,
                Err(e) => Some(e.to_string()),
            }
        }
    }

    #[test]
    fn ordinary_entries_survive_normalisation() {
        let blob = zip_of(&[
            ("config.json", b"{}".to_vec()),
            ("scripts/check_disk.ps1", b"Write-Output 'ok'".to_vec()),
        ]);
        let entries = read_zip_entries_within(&blob, 1024 * 1024).unwrap();
        let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["config.json", "scripts/check_disk.ps1"]);
    }
}
