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
    /// Every stored file, for the housekeeping sweep of files no row points at.
    async fn list(&self) -> Result<Vec<StoredBundleFile>>;
}

/// One file in the store, as [`BundleStore::list`] reports it.
#[derive(Debug, Clone)]
pub struct StoredBundleFile {
    pub tenant_id: i64,
    pub bundle_id: String,
    /// Last modified, unix seconds.
    pub modified: i64,
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

    async fn list(&self) -> Result<Vec<StoredBundleFile>> {
        let mut out = Vec::new();
        let mut tenants = match tokio::fs::read_dir(self.base.as_ref()).await {
            Ok(d) => d,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(tenant_dir) = tenants.next_entry().await? {
            // Only what this store writes: numeric tenant directories of `<id>.zip` files.
            let Some(tenant_id) = tenant_dir.file_name().to_str().and_then(|n| n.parse().ok())
            else {
                continue;
            };
            let mut files = tokio::fs::read_dir(tenant_dir.path()).await?;
            while let Some(file) = files.next_entry().await? {
                let name = file.file_name();
                let Some(bundle_id) = name.to_str().and_then(|n| n.strip_suffix(".zip")) else {
                    continue;
                };
                let modified = file
                    .metadata()
                    .await?
                    .modified()?
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64);
                out.push(StoredBundleFile {
                    tenant_id,
                    bundle_id: bundle_id.to_string(),
                    modified,
                });
            }
        }
        Ok(out)
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

/// A bundle id as the server mints them (a ULID). Checked before an id from a request is
/// used as a file name: the bundle token grammar allows `..`, this does not.
fn valid_bundle_id(s: &str) -> bool {
    s.len() == 26
        && s.bytes()
            .all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

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
fn check_resealed(
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
    let staged_id = fleet_core::bundlesig::new_bundle_id();
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
            &fleet_core::bundlesig::BundleDescriptor {
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
        crate::audit::record(
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
