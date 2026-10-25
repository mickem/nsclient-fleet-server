//! Write a tenant's groups and bundles out as a configuration directory, to keep in git,
//! to serve from with `CONFIG_SOURCE_DIR`, or to load into another server with
//! `--import-config`.
//!
//! What comes out loads back to the same thing: reconciling an export against the database
//! it came from changes nothing, so loading it back does not make agents download anything
//! again.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use fleet_core::crypto::encbundle;
use fleet_storage::{BundlesRepo, ConfigSourceRepo, Db, GroupsRepo};
use serde::Serialize;

use super::layout::{
    GroupBundleRef, GroupFile, BUNDLES_DIR, ENCRYPTED_EXT, GROUPS_DIR, PLAIN_BLOB_EXT,
};
use crate::bundles::{path_clash, read_zip_entries, BundleStore};

#[derive(Debug, Default, Serialize)]
pub struct ExportReport {
    pub groups: usize,
    /// Plain bundles written out as a tree of files.
    pub bundles_as_files: usize,
    /// Plain bundles written as the stored zip, because their contents could not be a
    /// portable tree — see [`ExportReport::notes`].
    pub bundles_as_zip: usize,
    pub bundles_encrypted: usize,
    pub notes: Vec<String>,
}

/// Export tenant `tenant_id` into `dir`, which may exist (a fresh clone, say) but must not
/// already have a `groups/` or `bundles/` in it.
pub async fn export(
    db: &Db,
    store: &dyn BundleStore,
    tenant_id: i64,
    dir: &Path,
) -> Result<ExportReport> {
    for sub in [GROUPS_DIR, BUNDLES_DIR] {
        if dir.join(sub).exists() {
            bail!(
                "{} already exists — export into a directory without {GROUPS_DIR}/ or {BUNDLES_DIR}/",
                dir.join(sub).display()
            );
        }
    }

    let bundles = BundlesRepo::new(db).list(tenant_id).await?;
    let groups = GroupsRepo::new(db).list(tenant_id).await?;
    let assignments = ConfigSourceRepo::new(db)
        .list_assignments(tenant_id)
        .await?;

    // Names that cannot be file names on every system the directory may be cloned to are
    // refused up front, before anything is written.
    let mut problems = Vec::new();
    let mut seen_names: HashMap<String, &str> = HashMap::new();
    for b in &bundles {
        for token in [&b.name, &b.version] {
            // A leading dot would also be skipped by the loader, as `.git` is.
            if !portable_component(token) || token.starts_with('.') {
                problems.push(format!(
                    "{}@{}: {token:?} cannot be a file name on every system",
                    b.name, b.version
                ));
            }
        }
        let folded = b.name.to_ascii_lowercase();
        match seen_names.get(&folded) {
            Some(other) if *other != b.name => problems.push(format!(
                "bundles {other:?} and {:?} differ only in case, and would be one directory \
                 on Windows or macOS — rename one first",
                b.name
            )),
            _ => {
                seen_names.insert(folded, &b.name);
            }
        }
    }
    let mut versions: HashSet<(String, String)> = HashSet::new();
    for b in &bundles {
        if !versions.insert((b.name.to_ascii_lowercase(), b.version.to_ascii_lowercase())) {
            problems.push(format!(
                "{} has versions that differ only in case — remove one first",
                b.name
            ));
        }
    }
    if !problems.is_empty() {
        bail!("cannot export:\n  - {}", problems.join("\n  - "));
    }

    let mut report = ExportReport::default();
    let bundles_root = dir.join(BUNDLES_DIR);
    std::fs::create_dir_all(&bundles_root)
        .with_context(|| format!("creating {}", bundles_root.display()))?;
    for b in &bundles {
        let bytes = store
            .get(tenant_id, &b.id)
            .await
            .with_context(|| format!("reading the stored bytes of {}@{}", b.name, b.version))?;
        let parent = bundles_root.join(&b.name);
        std::fs::create_dir_all(&parent)?;
        if b.format == encbundle::FORMAT_ENC_V1 {
            write(
                &parent.join(format!("{}.{ENCRYPTED_EXT}", b.version)),
                &bytes,
            )?;
            report.bundles_encrypted += 1;
            continue;
        }
        match as_tree(&bytes) {
            Ok(entries) => {
                let root = parent.join(&b.version);
                for (name, data) in entries {
                    write(&root.join(&name), &data)?;
                }
                report.bundles_as_files += 1;
            }
            Err(why) => {
                write(
                    &parent.join(format!("{}.{PLAIN_BLOB_EXT}", b.version)),
                    &bytes,
                )?;
                report
                    .notes
                    .push(format!("{}@{} kept as a zip: {why}", b.name, b.version));
                report.bundles_as_zip += 1;
            }
        }
    }

    let by_id: HashMap<&str, (&str, &str)> = bundles
        .iter()
        .map(|b| (b.id.as_str(), (b.name.as_str(), b.version.as_str())))
        .collect();
    let groups_root = dir.join(GROUPS_DIR);
    std::fs::create_dir_all(&groups_root)?;
    let mut used: HashSet<String> = HashSet::new();
    for g in &groups {
        let mut refs: Vec<GroupBundleRef> = assignments
            .iter()
            .filter(|(group_id, _, _)| *group_id == g.id)
            .filter_map(|(_, bundle_id, priority)| {
                by_id
                    .get(bundle_id.as_str())
                    .map(|(name, version)| GroupBundleRef {
                        name: name.to_string(),
                        version: version.to_string(),
                        priority: *priority,
                    })
            })
            .collect();
        refs.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
        let file = GroupFile {
            name: g.name.clone(),
            selector: serde_json::from_str(&g.selector_json)
                .with_context(|| format!("group {:?} has an unreadable selector", g.name))?,
            bundles: refs,
        };
        let mut json = serde_json::to_string_pretty(&file)?;
        json.push('\n');
        let stem = unique_stem(&group_file_stem(&g.name), &mut used);
        write(&groups_root.join(format!("{stem}.json")), json.as_bytes())?;
        report.groups += 1;
    }
    Ok(report)
}

fn write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, data).with_context(|| format!("writing {}", path.display()))
}

/// A stored plain bundle's files, if they can be written out as a tree that loads back to
/// the same files on any system. The reason why not otherwise.
fn as_tree(bytes: &[u8]) -> std::result::Result<Vec<(String, Vec<u8>)>, String> {
    let entries = read_zip_entries(bytes).map_err(|e| format!("not a readable zip ({e})"))?;
    if entries.is_empty() {
        return Err("the zip is empty".into());
    }
    let names: Vec<&str> = entries.iter().map(|(n, _)| n.as_str()).collect();
    let mut seen = HashSet::new();
    for name in &names {
        if !seen.insert(*name) {
            return Err(format!("{name:?} appears twice"));
        }
        if !name.split('/').all(portable_component) {
            return Err(format!("{name:?} cannot be a file name on every system"));
        }
        if let Some(other) = path_clash(name, &names) {
            return Err(format!(
                "{name:?} and {other:?} cannot both exist on Windows"
            ));
        }
    }
    if let Some((_, config)) = entries.iter().find(|(n, _)| n == "config.json") {
        // The loader insists on this, so a tree it would refuse is kept as a zip instead.
        if !serde_json::from_slice::<serde_json::Value>(config).is_ok_and(|v| v.is_object()) {
            return Err("config.json is not a JSON object".into());
        }
    }
    Ok(entries)
}

/// A path component every common file system will store as given. Trailing dots are out,
/// which also rules out `.` and `..`.
fn portable_component(s: &str) -> bool {
    const RESERVED: [&str; 22] = [
        "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
        "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
    ];
    let stem = s.split('.').next().unwrap_or("").to_ascii_lowercase();
    !s.is_empty()
        && !s.ends_with(['.', ' '])
        && !s
            .chars()
            .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*'))
        && !RESERVED.contains(&stem.as_str())
}

/// A file name for a group: its name, lowercased, with anything but letters and digits
/// made a `-`. The file name means nothing — the group's name is inside the file.
fn group_file_stem(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() || !portable_component(&out) {
        // Only the empty name and the device names get here: nothing else survives the
        // mapping above unportable.
        format!("group-{out}").trim_end_matches('-').to_string()
    } else {
        out
    }
}

fn unique_stem(stem: &str, used: &mut HashSet<String>) -> String {
    let mut candidate = stem.to_string();
    let mut n = 2;
    while !used.insert(candidate.clone()) {
        candidate = format!("{stem}-{n}");
        n += 1;
    }
    candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_file_names_are_tame_and_unique() {
        let mut used = HashSet::new();
        assert_eq!(
            unique_stem(&group_file_stem("SQL Servers (prod)"), &mut used),
            "sql-servers-prod"
        );
        assert_eq!(
            unique_stem(&group_file_stem("sql servers / prod"), &mut used),
            "sql-servers-prod-2"
        );
        assert_eq!(group_file_stem("!!!"), "group");
        assert_eq!(group_file_stem("CON"), "group-con");
    }

    #[test]
    fn components_that_some_system_would_mangle_are_not_portable() {
        for ok in [
            "config.json",
            "check_disk.ps1",
            "1.0.2",
            "a-b_c",
            ".gitkeep",
        ] {
            assert!(portable_component(ok), "{ok}");
        }
        for bad in ["", ".", "..", "1.", "a ", "a:b", "nul", "NUL.txt", "com1"] {
            assert!(!portable_component(bad), "{bad}");
        }
    }
}
