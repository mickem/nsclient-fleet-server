//! Make a tenant's groups, bundles and assignments match a configuration directory.
//!
//! The database stays what everything else reads — desired state, delivery, the UI — so
//! nothing downstream knows or cares where configuration came from. This is the whole of
//! `--import-config`.
//!
//! A bundle version is kept, id and all, when its contents have not changed, so an import
//! that changed one file does not make every agent download every bundle again. One whose
//! contents did change gets a new id and a new signature: bundle rows are immutable, and
//! the signature covers the digest.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;

use fleet_core::crypto::aead::MasterKey;
use fleet_core::crypto::bundlesig::{new_bundle_id, BundleDescriptor};
use fleet_core::crypto::digest::sha256_hex;
use fleet_core::crypto::encbundle;
use fleet_storage::{
    ApplyOutcome, BundleRow, BundlesRepo, ConfigPlan, ConfigSourceRepo, Db, GroupsRepo,
    PlannedBundle, PlannedGroup, TenantRepo,
};
use serde::Serialize;

use super::layout::{self, BundleContents};
use crate::bundles::{
    build_zip_from_entries, load_signing_key, read_zip_entries, sign_descriptor, BundleStore,
};

/// What reconciling did, or for a dry run would do. Bundles are `name@version`.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ReloadReport {
    /// False when the directory already matched the database: nothing was written and
    /// `config_version` did not move.
    pub changed: bool,
    pub dry_run: bool,
    pub bundles_added: Vec<String>,
    /// Same name and version, different contents: a new row and id replace the old.
    pub bundles_replaced: Vec<String>,
    pub bundles_removed: Vec<String>,
    pub bundles_unchanged: usize,
    pub groups_added: Vec<String>,
    pub groups_updated: Vec<String>,
    pub groups_removed: Vec<String>,
    pub groups_unchanged: usize,
    pub assignments_changed: bool,
}

#[derive(Debug)]
pub enum ReconcileError {
    /// The directory is wrong; nothing was changed. One message per problem.
    Invalid(Vec<String>),
    /// Groups or bundles were added or removed some other way while this ran.
    Changed,
    Internal(anyhow::Error),
}

impl std::fmt::Display for ReconcileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(errors) => {
                write!(f, "the configuration directory is invalid:")?;
                for e in errors {
                    write!(f, "\n  - {e}")?;
                }
                Ok(())
            }
            Self::Changed => write!(
                f,
                "groups or bundles changed while the directory was being applied — try again"
            ),
            Self::Internal(e) => write!(f, "{e:#}"),
        }
    }
}

impl From<anyhow::Error> for ReconcileError {
    fn from(e: anyhow::Error) -> Self {
        Self::Internal(e)
    }
}

/// Read `dir` and make tenant `tenant_id` match it. With `dry_run` nothing is written —
/// not the database, not the bundle store — and the report says what would have changed.
pub async fn reconcile(
    db: &Db,
    store: &dyn BundleStore,
    master_key: &MasterKey,
    tenant_id: i64,
    dir: &Path,
    dry_run: bool,
) -> Result<ReloadReport, ReconcileError> {
    let owned = dir.to_path_buf();
    let spec = tokio::task::spawn_blocking(move || layout::load(&owned))
        .await
        .map_err(|e| ReconcileError::Internal(e.into()))?
        .map_err(ReconcileError::Invalid)?;

    let tenant = TenantRepo::new(db)
        .get(tenant_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("tenant {tenant_id} does not exist"))?;
    let limits = fleet_core::tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());

    let existing_bundles = BundlesRepo::new(db).list(tenant_id).await?;
    let existing_groups = GroupsRepo::new(db).list(tenant_id).await?;
    let repo = ConfigSourceRepo::new(db);
    let existing_assignments = repo.list_assignments(tenant_id).await?;

    let built = build_bundles(spec.bundles, limits.max_bundle_mb)?;
    if built.len() as u64 > limits.max_bundles as u64 {
        return Err(ReconcileError::Invalid(vec![format!(
            "{} bundle versions, but the tier allows {}",
            built.len(),
            limits.max_bundles
        )]));
    }

    let mut report = ReloadReport {
        dry_run,
        ..Default::default()
    };
    let mut plan = ConfigPlan {
        expected_bundle_ids: existing_bundles.iter().map(|b| b.id.clone()).collect(),
        expected_group_ids: existing_groups.iter().map(|g| g.id.clone()).collect(),
        ..Default::default()
    };

    // Bundles: keep what is unchanged, replace what changed, add what is new.
    let by_identity: HashMap<(&str, &str), &BundleRow> = existing_bundles
        .iter()
        .map(|b| ((b.name.as_str(), b.version.as_str()), b))
        .collect();
    let mut bundle_ids: HashMap<(String, String), String> = HashMap::new();
    let mut kept: BTreeSet<String> = BTreeSet::new();
    let mut to_store: Vec<(String, Vec<u8>)> = Vec::new();
    let mut signing_key = None;
    for b in built {
        let label = format!("{}@{}", b.name, b.version);
        let current = by_identity
            .get(&(b.name.as_str(), b.version.as_str()))
            .copied();
        if let Some(row) = current {
            if unchanged(store, row, &b).await {
                kept.insert(row.id.clone());
                bundle_ids.insert((b.name, b.version), row.id.clone());
                report.bundles_unchanged += 1;
                continue;
            }
            report.bundles_replaced.push(label);
        } else {
            report.bundles_added.push(label);
        }

        let id = new_bundle_id();
        // A dry run signs nothing: the key is not needed to say what would change.
        let signature = if dry_run {
            String::new()
        } else {
            if signing_key.is_none() {
                signing_key = Some(load_signing_key(db, master_key, tenant_id).await?);
            }
            sign_descriptor(
                signing_key.as_ref().expect("loaded above"),
                &BundleDescriptor {
                    tenant_id,
                    bundle_id: &id,
                    name: &b.name,
                    version: &b.version,
                    format: b.format,
                    sha256_hex: &b.sha256,
                },
            )
        };
        plan.insert_bundles.push(PlannedBundle {
            id: id.clone(),
            name: b.name.clone(),
            version: b.version.clone(),
            sha256: b.sha256,
            size_bytes: b.bytes.len() as i64,
            signature,
            format: b.format.to_string(),
            key_fingerprint: b.key_fingerprint,
        });
        to_store.push((id.clone(), b.bytes));
        bundle_ids.insert((b.name, b.version), id);
    }
    for row in &existing_bundles {
        if !kept.contains(&row.id) {
            plan.delete_bundle_ids.push(row.id.clone());
            // A replaced version is already reported as such.
            let label = format!("{}@{}", row.name, row.version);
            if !report.bundles_replaced.contains(&label) {
                report.bundles_removed.push(label);
            }
        }
    }

    // Groups, matched by name, which is what the directory has.
    let groups_by_name: HashMap<&str, _> = existing_groups
        .iter()
        .map(|g| (g.name.as_str(), g))
        .collect();
    let mut group_ids: HashMap<String, String> = HashMap::new();
    for g in &spec.groups {
        let planned = match groups_by_name.get(g.name.as_str()) {
            Some(row) => {
                if row.selector_json == g.selector_json {
                    report.groups_unchanged += 1;
                } else {
                    report.groups_updated.push(g.name.clone());
                }
                PlannedGroup {
                    id: row.id.clone(),
                    name: g.name.clone(),
                    selector_json: g.selector_json.clone(),
                    create: false,
                }
            }
            None => {
                report.groups_added.push(g.name.clone());
                PlannedGroup {
                    id: ulid::Ulid::generate().to_string(),
                    name: g.name.clone(),
                    selector_json: g.selector_json.clone(),
                    create: true,
                }
            }
        };
        group_ids.insert(g.name.clone(), planned.id.clone());
        plan.groups.push(planned);
    }
    for row in &existing_groups {
        if !group_ids.contains_key(&row.name) {
            plan.delete_group_ids.push(row.id.clone());
            report.groups_removed.push(row.name.clone());
        }
    }

    for g in &spec.groups {
        for r in &g.bundles {
            // Both lookups are guaranteed by `layout::load`, which checked every reference.
            let bundle_id = &bundle_ids[&(r.name.clone(), r.version.clone())];
            plan.assignments
                .push((group_ids[&g.name].clone(), bundle_id.clone(), r.priority));
        }
    }
    let mut before = existing_assignments;
    before.sort();
    let mut after = plan.assignments.clone();
    after.sort();
    report.assignments_changed = before != after;

    report.changed = !plan.insert_bundles.is_empty()
        || !plan.delete_bundle_ids.is_empty()
        || !report.groups_added.is_empty()
        || !report.groups_updated.is_empty()
        || !report.groups_removed.is_empty()
        || report.assignments_changed;
    if dry_run || !report.changed {
        return Ok(report);
    }

    // Bytes before rows: a row is never visible without its file. If anything below fails
    // these are files no row points at, which the housekeeping sweep removes.
    for (id, bytes) in &to_store {
        if let Err(e) = store.put(tenant_id, id, bytes).await {
            discard(store, tenant_id, &to_store).await;
            return Err(ReconcileError::Internal(e.context("storing bundle bytes")));
        }
    }
    match repo.apply(tenant_id, &plan).await {
        Ok(ApplyOutcome::Applied) => {}
        Ok(ApplyOutcome::Changed) => {
            discard(store, tenant_id, &to_store).await;
            return Err(ReconcileError::Changed);
        }
        Err(e) => {
            discard(store, tenant_id, &to_store).await;
            return Err(ReconcileError::Internal(e));
        }
    }
    // After the commit, for the reason `delete_bundle` gives: a row without its file is a
    // bundle that fails to download, a file without its row is only wasted space.
    for id in &plan.delete_bundle_ids {
        if let Err(e) = store.delete(tenant_id, id).await {
            tracing::warn!(error = %e, bundle_id = %id, "replaced bundle bytes could not be removed");
        }
    }
    Ok(report)
}

/// A bundle from the directory, made into what would be stored.
struct BuiltBundle {
    name: String,
    version: String,
    format: &'static str,
    bytes: Vec<u8>,
    sha256: String,
    key_fingerprint: Option<String>,
    /// The files, for a tree: compared against a stored zip whose bytes differ only in how
    /// they were zipped (an export, then an import).
    tree: Option<Vec<(String, Vec<u8>)>>,
}

fn build_bundles(
    specs: Vec<layout::BundleSpec>,
    max_bundle_mb: u32,
) -> Result<Vec<BuiltBundle>, ReconcileError> {
    let max = max_bundle_mb as usize * 1024 * 1024;
    let mut errors = Vec::new();
    let mut out = Vec::new();
    for spec in specs {
        let label = format!("{}@{}", spec.name, spec.version);
        let (format, bytes, key_fingerprint, tree) = match spec.contents {
            BundleContents::Tree(files) => match build_zip_from_entries(&files) {
                Ok(bytes) => (encbundle::FORMAT_PLAIN, bytes, None, Some(files)),
                Err(e) => {
                    errors.push(format!("{label}: could not be zipped: {e}"));
                    continue;
                }
            },
            BundleContents::PlainBlob(bytes) => {
                // The same rule upload applies: agents trust the magic over the format, so a
                // sealed blob must never be stored as plain.
                if encbundle::is_encrypted(&bytes) {
                    errors.push(format!(
                        "{label}: the .{} file is an encrypted bundle — name it .{}",
                        layout::PLAIN_BLOB_EXT,
                        layout::ENCRYPTED_EXT
                    ));
                    continue;
                }
                (encbundle::FORMAT_PLAIN, bytes, None, None)
            }
            BundleContents::Encrypted(bytes) => match encbundle::parse_header(&bytes) {
                Ok(h) => (
                    encbundle::FORMAT_ENC_V1,
                    bytes,
                    Some(h.fingerprint_hex()),
                    None,
                ),
                Err(e) => {
                    errors.push(format!("{label}: not a valid encrypted bundle: {e}"));
                    continue;
                }
            },
        };
        if bytes.len() > max {
            errors.push(format!(
                "{label}: {} bytes, over the tier's {max_bundle_mb} MB",
                bytes.len()
            ));
            continue;
        }
        out.push(BuiltBundle {
            name: spec.name,
            version: spec.version,
            format,
            sha256: sha256_hex(&bytes),
            bytes,
            key_fingerprint,
            tree,
        });
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(ReconcileError::Invalid(errors))
    }
}

/// Whether `row` already holds what `b` would store.
async fn unchanged(store: &dyn BundleStore, row: &BundleRow, b: &BuiltBundle) -> bool {
    if row.format != b.format {
        return false;
    }
    if row.sha256 == b.sha256 {
        return true;
    }
    // A tree is equal to a stored zip with the same files, however that zip was made.
    let Some(tree) = &b.tree else {
        return false;
    };
    let Ok(stored) = store.get(row.tenant_id, &row.id).await else {
        return false;
    };
    let Ok(mut entries) = read_zip_entries(&stored) else {
        return false;
    };
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    &entries == tree
}

async fn discard(store: &dyn BundleStore, tenant_id: i64, stored: &[(String, Vec<u8>)]) {
    for (id, _) in stored {
        let _ = store.delete(tenant_id, id).await;
    }
}
