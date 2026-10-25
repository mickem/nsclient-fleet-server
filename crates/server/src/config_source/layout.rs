//! The configuration directory: what it looks like on disk and how it is read.
//!
//! ```text
//! <dir>/
//!   groups/<anything>.json         one group: name, selector, assigned bundles
//!   bundles/<name>/<version>/      a plain bundle as a tree of files, zipped as it stands
//!   bundles/<name>/<version>.zip   a plain bundle stored as it is
//!   bundles/<name>/<version>.nseb  an encrypted bundle (NSEB1 envelope) stored as it is
//! ```
//!
//! Names beginning with `.` are skipped at the top two levels (`.git`, `.gitkeep`), as is
//! anything at the top level other than `groups/` and `bundles/`, so the directory can be a
//! repository with a README in it. Inside a bundle tree nothing is skipped: what is in the
//! directory is what agents receive.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::bundles::{valid_bundle_token, MAX_INFLATED_TOTAL, MAX_ZIP_ENTRIES};

pub(crate) const GROUPS_DIR: &str = "groups";
pub(crate) const BUNDLES_DIR: &str = "bundles";
pub(crate) const PLAIN_BLOB_EXT: &str = "zip";
pub(crate) const ENCRYPTED_EXT: &str = "nseb";

/// What a file under `groups/` holds.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupFile {
    pub name: String,
    /// The same selector the API takes, e.g. `{"clauses": [...]}`.
    pub selector: serde_json::Value,
    #[serde(default)]
    pub bundles: Vec<GroupBundleRef>,
}

/// A bundle version assigned to a group, by name and version: the directory has no ids.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct GroupBundleRef {
    pub name: String,
    pub version: String,
    #[serde(default = "default_priority")]
    pub priority: i64,
}

fn default_priority() -> i64 {
    100
}

#[derive(Debug)]
pub(crate) struct Spec {
    pub bundles: Vec<BundleSpec>,
    pub groups: Vec<GroupSpec>,
}

#[derive(Debug)]
pub(crate) struct BundleSpec {
    pub name: String,
    pub version: String,
    pub contents: BundleContents,
}

#[derive(Debug)]
pub(crate) enum BundleContents {
    /// Files by `/`-separated path, sorted by path.
    Tree(Vec<(String, Vec<u8>)>),
    PlainBlob(Vec<u8>),
    Encrypted(Vec<u8>),
}

#[derive(Debug)]
pub(crate) struct GroupSpec {
    pub name: String,
    /// The selector as the database stores it: parsed, validated and re-serialized.
    pub selector_json: String,
    pub bundles: Vec<GroupBundleRef>,
}

/// Read and check the whole directory. Every problem found is reported, not just the first:
/// a directory is usually loaded after a commit, and fixing one error per round trip is a
/// poor way to find the other three.
pub(crate) fn load(dir: &Path) -> Result<Spec, Vec<String>> {
    let mut errors = Vec::new();
    if !dir.is_dir() {
        return Err(vec![format!("{} is not a directory", dir.display())]);
    }
    let groups_dir = dir.join(GROUPS_DIR);
    let bundles_dir = dir.join(BUNDLES_DIR);
    // A directory with neither is far more likely a wrong path than a wish to delete every
    // group and bundle, which is what loading it would do.
    if !groups_dir.is_dir() && !bundles_dir.is_dir() {
        return Err(vec![format!(
            "{} has neither a {GROUPS_DIR}/ nor a {BUNDLES_DIR}/ directory — refusing to treat \
             it as an empty configuration",
            dir.display()
        )]);
    }

    let bundles = if bundles_dir.is_dir() {
        load_bundles(&bundles_dir, &mut errors)
    } else {
        Vec::new()
    };
    let groups = if groups_dir.is_dir() {
        load_groups(&groups_dir, &mut errors)
    } else {
        Vec::new()
    };

    // References are checked here rather than at planning time so that a bad reference is
    // reported alongside every other problem in the directory.
    let known: HashSet<(&str, &str)> = bundles
        .iter()
        .map(|b| (b.name.as_str(), b.version.as_str()))
        .collect();
    for g in &groups {
        for r in &g.bundles {
            if !known.contains(&(r.name.as_str(), r.version.as_str())) {
                errors.push(format!(
                    "group {:?} assigns {}@{}, which is not under {BUNDLES_DIR}/",
                    g.name, r.name, r.version
                ));
            }
        }
    }

    if errors.is_empty() {
        Ok(Spec { bundles, groups })
    } else {
        Err(errors)
    }
}

fn load_bundles(bundles_dir: &Path, errors: &mut Vec<String>) -> Vec<BundleSpec> {
    let mut out = Vec::new();
    for (name, path) in list_dir(bundles_dir, errors) {
        let shown = format!("{BUNDLES_DIR}/{name}");
        if !is_real_dir(&path) {
            errors.push(format!(
                "{shown}: expected a directory per bundle, holding its versions"
            ));
            continue;
        }
        if !valid_bundle_token(&name) {
            errors.push(format!(
                "{shown}: bundle names are 1-128 letters, digits, '.', '_' or '-'"
            ));
            continue;
        }
        // Keyed by version, so a version present twice — as a tree and as a file — is caught.
        let mut versions: BTreeMap<String, BundleContents> = BTreeMap::new();
        for (entry, entry_path) in list_dir(&path, errors) {
            let shown = format!("{shown}/{entry}");
            let (version, contents) = if is_real_dir(&entry_path) {
                match read_tree(&entry_path, &shown) {
                    Ok(files) => (entry.clone(), BundleContents::Tree(files)),
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                }
            } else if let Some(v) = entry.strip_suffix(&format!(".{PLAIN_BLOB_EXT}")) {
                match read_file(&entry_path, &shown) {
                    Ok(b) => (v.to_string(), BundleContents::PlainBlob(b)),
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                }
            } else if let Some(v) = entry.strip_suffix(&format!(".{ENCRYPTED_EXT}")) {
                match read_file(&entry_path, &shown) {
                    Ok(b) => (v.to_string(), BundleContents::Encrypted(b)),
                    Err(e) => {
                        errors.push(e);
                        continue;
                    }
                }
            } else {
                errors.push(format!(
                    "{shown}: expected a version directory, <version>.{PLAIN_BLOB_EXT} or \
                     <version>.{ENCRYPTED_EXT}"
                ));
                continue;
            };
            if !valid_bundle_token(&version) {
                errors.push(format!(
                    "{shown}: versions are 1-128 letters, digits, '.', '_' or '-'"
                ));
                continue;
            }
            if versions.contains_key(&version) {
                errors.push(format!(
                    "{shown}: version {version} is given more than once"
                ));
                continue;
            }
            versions.insert(version, contents);
        }
        for (version, contents) in versions {
            out.push(BundleSpec {
                name: name.clone(),
                version,
                contents,
            });
        }
    }
    out
}

fn load_groups(groups_dir: &Path, errors: &mut Vec<String>) -> Vec<GroupSpec> {
    let mut out: Vec<GroupSpec> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for (file, path) in list_dir(groups_dir, errors) {
        let shown = format!("{GROUPS_DIR}/{file}");
        if !file.ends_with(".json") || is_real_dir(&path) {
            errors.push(format!("{shown}: expected <group>.json files only"));
            continue;
        }
        let bytes = match read_file(&path, &shown) {
            Ok(b) => b,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        let parsed: GroupFile = match serde_json::from_slice(&bytes) {
            Ok(g) => g,
            Err(e) => {
                errors.push(format!("{shown}: {e}"));
                continue;
            }
        };
        let name = parsed.name.trim().to_string();
        // The API's rule for a group name.
        if name.is_empty() || name.len() > 128 {
            errors.push(format!("{shown}: name must be 1-128 characters"));
            continue;
        }
        if !seen.insert(name.clone()) {
            errors.push(format!(
                "{shown}: another file already defines group {name:?}"
            ));
            continue;
        }
        let selector = match fleet_core::selector::Selector::from_json(&parsed.selector) {
            Ok(s) => s,
            Err(e) => {
                errors.push(format!("{shown}: bad selector: {e}"));
                continue;
            }
        };
        let selector_json = serde_json::to_string(&selector).unwrap_or_else(|_| "{}".into());
        let mut refs = HashSet::new();
        for r in &parsed.bundles {
            if !refs.insert((r.name.clone(), r.version.clone())) {
                errors.push(format!(
                    "{shown}: {}@{} is assigned more than once",
                    r.name, r.version
                ));
            }
        }
        out.push(GroupSpec {
            name,
            selector_json,
            bundles: parsed.bundles,
        });
    }
    out
}

/// The entries of `dir` by name, sorted, skipping dot-names. A name that is not UTF-8 is
/// reported: it could not be a bundle name, version or group file anyway.
fn list_dir(dir: &Path, errors: &mut Vec<String>) -> Vec<(String, PathBuf)> {
    let read = match std::fs::read_dir(dir) {
        Ok(r) => r,
        Err(e) => {
            errors.push(format!("{}: {e}", dir.display()));
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for entry in read {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                errors.push(format!("{}: {e}", dir.display()));
                continue;
            }
        };
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            errors.push(format!(
                "{}: a name is not valid UTF-8",
                entry.path().display()
            ));
            continue;
        };
        if name.starts_with('.') {
            continue;
        }
        out.push((name, entry.path()));
    }
    out.sort();
    out
}

/// A directory, and not a link to one. Links are refused everywhere below: a link in a
/// repository could otherwise pull `/etc/shadow` into a bundle we sign and ship.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

fn read_file(path: &Path, shown: &str) -> Result<Vec<u8>, String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| format!("{shown}: {e}"))?;
    if !meta.is_file() {
        return Err(format!(
            "{shown}: not a regular file (links are not followed)"
        ));
    }
    if meta.len() > MAX_INFLATED_TOTAL {
        return Err(format!(
            "{shown}: larger than {} MiB",
            MAX_INFLATED_TOTAL / (1024 * 1024)
        ));
    }
    std::fs::read(path).map_err(|e| format!("{shown}: {e}"))
}

/// Every file under `root`, by `/`-joined relative path, sorted. Bounded the same way an
/// uploaded zip is when it is opened: by entry count and by total size.
fn read_tree(root: &Path, shown: &str) -> Result<Vec<(String, Vec<u8>)>, String> {
    let mut out = Vec::new();
    let mut budget = MAX_INFLATED_TOTAL;
    let mut stack = vec![(root.to_path_buf(), String::new())];
    while let Some((dir, prefix)) = stack.pop() {
        let read = std::fs::read_dir(&dir).map_err(|e| format!("{shown}/{prefix}: {e}"))?;
        for entry in read {
            let entry = entry.map_err(|e| format!("{shown}/{prefix}: {e}"))?;
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                return Err(format!("{shown}/{prefix}: a name is not valid UTF-8"));
            };
            let rel = if prefix.is_empty() {
                name
            } else {
                format!("{prefix}/{name}")
            };
            let meta = std::fs::symlink_metadata(entry.path())
                .map_err(|e| format!("{shown}/{rel}: {e}"))?;
            if meta.is_dir() {
                stack.push((entry.path(), rel));
                continue;
            }
            if !meta.is_file() {
                return Err(format!(
                    "{shown}/{rel}: not a regular file (links are not followed)"
                ));
            }
            if out.len() >= MAX_ZIP_ENTRIES {
                return Err(format!("{shown}: more than {MAX_ZIP_ENTRIES} files"));
            }
            if meta.len() > budget {
                return Err(format!(
                    "{shown}: larger than {} MiB in total",
                    MAX_INFLATED_TOTAL / (1024 * 1024)
                ));
            }
            let data = std::fs::read(entry.path()).map_err(|e| format!("{shown}/{rel}: {e}"))?;
            budget = budget.saturating_sub(data.len() as u64);
            out.push((rel, data));
        }
    }
    if out.is_empty() {
        return Err(format!("{shown}: the version directory is empty"));
    }
    if let Some((_, config)) = out.iter().find(|(n, _)| n == "config.json") {
        match serde_json::from_slice::<serde_json::Value>(config) {
            Ok(v) if v.is_object() => {}
            Ok(_) => return Err(format!("{shown}/config.json: must be a JSON object")),
            Err(e) => return Err(format!("{shown}/config.json: {e}")),
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(root: &Path, rel: &str, data: &[u8]) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, data).unwrap();
    }

    const SELECTOR: &str = r#"{"clauses":[{"op":"eq","key":"os","value":"windows"}]}"#;

    #[test]
    fn reads_every_bundle_form_and_group() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        write(root, "README.md", b"ignored");
        write(root, ".git/HEAD", b"ignored");
        write(root, "bundles/base/1/config.json", b"{}");
        write(root, "bundles/base/1/scripts/a.ps1", b"x");
        write(root, "bundles/base/2.zip", b"PK-ish");
        write(root, "bundles/secret/1.nseb", b"NSEB1...");
        write(root, "bundles/.gitkeep", b"");
        write(
            root,
            "groups/win.json",
            format!(
                r#"{{"name":"win","selector":{SELECTOR},"bundles":[{{"name":"base","version":"1"}}]}}"#
            )
            .as_bytes(),
        );

        let spec = load(root).unwrap();
        let ids: Vec<String> = spec
            .bundles
            .iter()
            .map(|b| format!("{}@{}", b.name, b.version))
            .collect();
        assert_eq!(ids, ["base@1", "base@2", "secret@1"]);
        let BundleContents::Tree(files) = &spec.bundles[0].contents else {
            panic!("expected a tree");
        };
        let names: Vec<&str> = files.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["config.json", "scripts/a.ps1"]);
        assert!(matches!(
            spec.bundles[1].contents,
            BundleContents::PlainBlob(_)
        ));
        assert!(matches!(
            spec.bundles[2].contents,
            BundleContents::Encrypted(_)
        ));
        assert_eq!(spec.groups.len(), 1);
        assert_eq!(spec.groups[0].bundles[0].priority, 100);
    }

    #[test]
    fn a_directory_with_neither_subdirectory_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        write(dir.path(), "README.md", b"x");
        let errors = load(dir.path()).unwrap_err();
        assert!(errors[0].contains("refusing"), "{errors:?}");
    }

    #[test]
    fn every_problem_is_reported_at_once() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        write(root, "bundles/base/1/config.json", b"[]");
        write(root, "bundles/base/2/config.json", b"{}");
        write(root, "bundles/base/2.zip", b"x");
        write(root, "bundles/base/notes.txt", b"x");
        write(
            root,
            "groups/a.json",
            br#"{"name":"a","selector":{"clauses":[]},"extra":1}"#,
        );
        write(
            root,
            "groups/b.json",
            br#"{"name":"b","selector":{"clauses":[]},"bundles":[{"name":"base","version":"9"}]}"#,
        );
        write(root, "groups/c.yaml", b"x");
        let errors = load(root).unwrap_err();
        let all = errors.join("\n");
        for needle in [
            "1/config.json: must be a JSON object",
            "given more than once",
            "notes.txt: expected a version directory",
            "unknown field `extra`",
            "assigns base@9",
            "c.yaml: expected <group>.json",
        ] {
            assert!(all.contains(needle), "missing {needle:?} in:\n{all}");
        }
    }

    #[test]
    fn duplicate_group_names_are_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        write(
            root,
            "groups/a.json",
            br#"{"name":"same","selector":{"clauses":[]}}"#,
        );
        write(
            root,
            "groups/b.json",
            br#"{"name":" same ","selector":{"clauses":[]}}"#,
        );
        let errors = load(root).unwrap_err();
        assert!(errors[0].contains("already defines"), "{errors:?}");
    }

    #[cfg(unix)]
    #[test]
    fn links_are_not_followed() {
        let dir = tempfile::TempDir::new().unwrap();
        let root = dir.path();
        write(root, "outside/secret", b"s");
        write(root, "bundles/base/1/config.json", b"{}");
        std::os::unix::fs::symlink(
            root.join("outside/secret"),
            root.join("bundles/base/1/stolen"),
        )
        .unwrap();
        let errors = load(root).unwrap_err();
        assert!(errors[0].contains("links are not followed"), "{errors:?}");
    }
}
