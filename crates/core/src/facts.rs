//! Host facts: the inventory document an agent uploads about the machine it runs on.
//!
//! The wire contract is the agent's (NSClient++ `libs/onboarding/sync.cpp`), and this module
//! is the server's side of it:
//!
//! * Every desired-state poll and state report carries `facts_hash`, the SHA-256 hex of the
//!   agent's current document. The server answers with the hash *it* holds in the
//!   [`FACTS_HASH_HEADER`] response header, `none` when it holds nothing.
//! * The agent uploads the document only when the two differ, as
//!   `{"collected_at":"<ts>","facts":<document>,"facts_hash":"<hex>"}`, where `facts_hash`
//!   is the digest of the `facts` value *exactly as it appears in the body*. The server
//!   therefore checks the digest against the raw bytes ([`parse_upload`]) and stores those
//!   bytes verbatim — re-encoding would be free to reorder a key or respell a number, after
//!   which the stored document would no longer match the hash it was filed under.
//!
//! Documents are compared with [`diff`], which matches list records by their `id` (the
//! document rules require one, unique and stable) so that "this package appeared" reads as
//! one added record rather than a list that shifted by one.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use serde_json::{Map, Value};

pub use crate::digest::sha256_hex;
use std::collections::{BTreeSet, HashMap};

/// Response header carrying the hash of the document the server holds for this host.
/// Lowercase, as the agent looks it up.
pub const FACTS_HASH_HEADER: &str = "x-facts-hash";

/// Header value meaning "the server holds no document for this host".
pub const FACTS_HASH_NONE: &str = "none";

/// The source of the agent's own document: the one uploaded over mTLS, and the only one
/// the hash exchange covers. Other sources (imports, cloud inventories, the API) store
/// their documents beside it under their own names; see [`valid_source`].
pub const AGENT_SOURCE: &str = "agent";

/// Longest source name.
pub const MAX_SOURCE_LEN: usize = 64;

/// Whether `s` can name a facts source: lowercase ASCII letters and digits, with `_ . : -`
/// inside (`agent`, `import:cmdb`, `aws:prod-eu`), at most [`MAX_SOURCE_LEN`] characters.
/// Source names are stored and rendered, so they are kept to a charset that needs no
/// escaping anywhere.
pub fn valid_source(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_SOURCE_LEN
        && b[0].is_ascii_lowercase()
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'.' | b':' | b'-')
        })
}

/// `sha256("{}")`: the hash of a host with no fact set enabled.
pub const EMPTY_FACTS_HASH: &str =
    "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

/// Longest `collected_at` stored. It is an ISO 8601 timestamp; anything longer is not one.
pub const MAX_COLLECTED_AT_LEN: usize = 64;

/// A facts hash as the agent may send it: 64 hex digits, returned lowercase so it compares
/// directly against what we computed. Anything else is `None`.
pub fn normalize_hash(h: &str) -> Option<String> {
    if h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(h.to_ascii_lowercase())
    } else {
        None
    }
}

/// A verified upload. `facts` is the document's bytes exactly as they arrived.
#[derive(Debug)]
pub struct FactsUpload<'a> {
    pub facts_hash: String,
    pub collected_at: Option<String>,
    pub facts: &'a str,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UploadError {
    #[error("body is not a facts upload: {0}")]
    Malformed(String),
    #[error("facts_hash must be 64 hex characters")]
    BadHash,
    #[error("facts must be a JSON object")]
    NotAnObject,
    #[error("facts_hash does not match the facts document")]
    HashMismatch,
}

#[derive(Deserialize)]
struct RawUpload<'a> {
    facts_hash: String,
    #[serde(default)]
    collected_at: Option<String>,
    #[serde(borrow)]
    facts: &'a RawValue,
}

/// Parse and verify a `/agent/v1/facts` body.
///
/// The hash is checked against the raw bytes of the `facts` member, which is what the agent
/// hashed. Only the shape is checked beyond that: the agent's core already enforced the
/// document rules, and a server that rejected a set it did not understand would lose the
/// whole inventory over one new producer.
pub fn parse_upload(body: &[u8]) -> Result<FactsUpload<'_>, UploadError> {
    let raw: RawUpload<'_> =
        serde_json::from_slice(body).map_err(|e| UploadError::Malformed(e.to_string()))?;
    let facts_hash = normalize_hash(&raw.facts_hash).ok_or(UploadError::BadHash)?;
    let facts = raw.facts.get();
    if !facts.starts_with('{') {
        return Err(UploadError::NotAnObject);
    }
    if sha256_hex(facts.as_bytes()) != facts_hash {
        return Err(UploadError::HashMismatch);
    }
    let collected_at = raw
        .collected_at
        .map(|c| {
            c.trim()
                .chars()
                .take(MAX_COLLECTED_AT_LEN)
                .collect::<String>()
        })
        .filter(|c| !c.is_empty());
    Ok(FactsUpload {
        facts_hash,
        collected_at,
        facts,
    })
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    Added,
    Removed,
    Changed,
}

/// One difference between two documents.
///
/// `path` is dotted, with list records addressed by id: `software.installed[bash].version`.
/// `old`/`new` carry the value when it is short enough to be worth showing (a scalar, or a
/// short list of scalars); a whole added or removed record or section is named, not copied.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FactChange {
    pub path: String,
    pub kind: ChangeKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new: Option<Value>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct FactsDiff {
    pub changes: Vec<FactChange>,
    /// Changes found beyond the cap and not listed.
    #[serde(default)]
    pub truncated: usize,
}

impl FactsDiff {
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty() && self.truncated == 0
    }
}

/// Longest string value copied into a change; longer ones are cut with an ellipsis.
const MAX_SHOWN_STRING: usize = 200;
/// Longest list of scalars copied into a change.
const MAX_SHOWN_LIST: usize = 16;

/// Differences from `old` to `new`, at most `max_changes` of them listed.
pub fn diff(old: &Value, new: &Value, max_changes: usize) -> FactsDiff {
    let mut d = Differ {
        out: FactsDiff::default(),
        max: max_changes,
    };
    d.value("", old, new);
    d.out
}

struct Differ {
    out: FactsDiff,
    max: usize,
}

impl Differ {
    fn push(&mut self, path: String, kind: ChangeKind, old: Option<&Value>, new: Option<&Value>) {
        if self.out.changes.len() >= self.max {
            self.out.truncated += 1;
            return;
        }
        self.out.changes.push(FactChange {
            path,
            kind,
            old: old.and_then(shown),
            new: new.and_then(shown),
        });
    }

    fn value(&mut self, path: &str, old: &Value, new: &Value) {
        match (old, new) {
            (Value::Object(o), Value::Object(n)) => self.object(path, o, n),
            (Value::Array(o), Value::Array(n)) => match (record_ids(o), record_ids(n)) {
                (Some(oi), Some(ni)) => self.records(path, o, &oi, n, &ni),
                _ if o == n => {}
                _ => self.push(path.to_owned(), ChangeKind::Changed, Some(old), Some(new)),
            },
            _ if old == new => {}
            _ => self.push(path.to_owned(), ChangeKind::Changed, Some(old), Some(new)),
        }
    }

    fn object(&mut self, path: &str, old: &Map<String, Value>, new: &Map<String, Value>) {
        // Sorted explicitly: serde_json's map is only sorted without `preserve_order`, and
        // any crate in the build may turn that on.
        let keys: BTreeSet<&String> = old.keys().chain(new.keys()).collect();
        for k in keys {
            let p = join(path, k);
            match (old.get(k), new.get(k)) {
                (Some(o), Some(n)) => self.value(&p, o, n),
                (Some(o), None) => self.push(p, ChangeKind::Removed, Some(o), None),
                (None, Some(n)) => self.push(p, ChangeKind::Added, None, Some(n)),
                (None, None) => unreachable!(),
            }
        }
    }

    fn records(
        &mut self,
        path: &str,
        old: &[Value],
        old_ids: &[&str],
        new: &[Value],
        new_ids: &[&str],
    ) {
        let old_by_id: HashMap<&str, &Value> = old_ids.iter().copied().zip(old.iter()).collect();
        let new_set: BTreeSet<&str> = new_ids.iter().copied().collect();
        for (id, v) in old_ids.iter().zip(old) {
            if !new_set.contains(id) {
                self.push(record_path(path, id), ChangeKind::Removed, Some(v), None);
            }
        }
        for (id, v) in new_ids.iter().zip(new) {
            let p = record_path(path, id);
            match old_by_id.get(id) {
                Some(o) => self.value(&p, o, v),
                None => self.push(p, ChangeKind::Added, None, Some(v)),
            }
        }
    }
}

fn join(path: &str, key: &str) -> String {
    if path.is_empty() {
        key.to_owned()
    } else {
        format!("{path}.{key}")
    }
}

fn record_path(path: &str, id: &str) -> String {
    format!("{path}[{id}]")
}

/// The ids of a list of records, or `None` if this is not one: every element an object with
/// a string `id`, unique in the list. An empty list qualifies — it is a record list that
/// currently has no records, and diffing it against a full one should list the records.
fn record_ids(list: &[Value]) -> Option<Vec<&str>> {
    let mut ids = Vec::with_capacity(list.len());
    let mut seen = BTreeSet::new();
    for v in list {
        let id = v.as_object()?.get("id")?.as_str()?;
        if !seen.insert(id) {
            return None;
        }
        ids.push(id);
    }
    Some(ids)
}

/// The value as it is worth showing in a change, or `None` for one too big to copy.
fn shown(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) => Some(Value::String(clip(s))),
        Value::Number(_) | Value::Bool(_) | Value::Null => Some(v.clone()),
        Value::Array(a)
            if a.len() <= MAX_SHOWN_LIST && a.iter().all(|x| !x.is_object() && !x.is_array()) =>
        {
            Some(Value::Array(
                a.iter()
                    .map(|x| match x {
                        Value::String(s) => Value::String(clip(s)),
                        other => other.clone(),
                    })
                    .collect(),
            ))
        }
        _ => None,
    }
}

fn clip(s: &str) -> String {
    if s.chars().count() <= MAX_SHOWN_STRING {
        s.to_owned()
    } else {
        let mut c: String = s.chars().take(MAX_SHOWN_STRING).collect();
        c.push('…');
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn empty_document_hash_matches_the_agent() {
        assert_eq!(sha256_hex(b"{}"), EMPTY_FACTS_HASH);
    }

    #[test]
    fn source_names() {
        for ok in [AGENT_SOURCE, "import:cmdb", "aws:prod-eu", "gcp.project_1"] {
            assert!(valid_source(ok), "{ok}");
        }
        for bad in ["", "Agent", "1st", ":x", "a b", "a/b", &"a".repeat(65)] {
            assert!(!valid_source(bad), "{bad}");
        }
    }

    #[test]
    fn normalize_hash_accepts_hex_only() {
        assert_eq!(
            normalize_hash(&"A".repeat(64)).as_deref(),
            Some("a".repeat(64).as_str())
        );
        assert!(normalize_hash("abc").is_none());
        assert!(normalize_hash(&format!("{}g", "a".repeat(63))).is_none());
        assert!(normalize_hash(&"a".repeat(65)).is_none());
        assert!(normalize_hash("none").is_none());
    }

    fn upload(facts: &str, hash: &str) -> Vec<u8> {
        format!(
            "{{\"collected_at\":\"2026-09-25T10:00:00Z\",\"facts\":{facts},\"facts_hash\":\"{hash}\"}}"
        )
        .into_bytes()
    }

    #[test]
    fn upload_is_verified_against_the_raw_bytes() {
        // A number spelling and key order a re-encode would not preserve.
        let facts = r#"{"os":{"family":"linux","version":"6.1"},"hardware":{"memory_gb":3.50}}"#;
        let body = upload(facts, &sha256_hex(facts.as_bytes()));
        let u = parse_upload(&body).unwrap();
        assert_eq!(u.facts, facts);
        assert_eq!(u.collected_at.as_deref(), Some("2026-09-25T10:00:00Z"));
        assert_eq!(u.facts_hash, sha256_hex(facts.as_bytes()));
    }

    #[test]
    fn upload_hash_may_arrive_uppercase() {
        let facts = "{}";
        let body = upload(facts, &EMPTY_FACTS_HASH.to_ascii_uppercase());
        assert_eq!(parse_upload(&body).unwrap().facts_hash, EMPTY_FACTS_HASH);
    }

    #[test]
    fn upload_with_the_wrong_hash_is_refused() {
        let body = upload(r#"{"os":{}}"#, EMPTY_FACTS_HASH);
        assert_eq!(parse_upload(&body).unwrap_err(), UploadError::HashMismatch);
    }

    #[test]
    fn upload_shapes_are_checked() {
        let body = upload("[]", &sha256_hex(b"[]"));
        assert_eq!(parse_upload(&body).unwrap_err(), UploadError::NotAnObject);
        let body = upload("{}", "short");
        assert_eq!(parse_upload(&body).unwrap_err(), UploadError::BadHash);
        assert!(matches!(
            parse_upload(b"{\"facts\":{}}"),
            Err(UploadError::Malformed(_))
        ));
        assert!(matches!(
            parse_upload(b"not json"),
            Err(UploadError::Malformed(_))
        ));
    }

    #[test]
    fn upload_without_collected_at_is_accepted() {
        let body = format!("{{\"facts\":{{}},\"facts_hash\":\"{EMPTY_FACTS_HASH}\"}}");
        assert!(parse_upload(body.as_bytes())
            .unwrap()
            .collected_at
            .is_none());
    }

    #[test]
    fn identical_documents_have_no_diff() {
        let d = json!({"os": {"family": "linux"}, "storage": {"volumes": [{"id": "/"}]}});
        assert!(diff(&d, &d, 100).is_empty());
    }

    #[test]
    fn records_are_matched_by_id() {
        let old = json!({"software": {"installed": [
            {"id": "bash", "version": "5.1"},
            {"id": "curl", "version": "7.0"},
            {"id": "vim", "version": "9.0"},
        ]}});
        let new = json!({"software": {"installed": [
            {"id": "bash", "version": "5.2"},
            {"id": "vim", "version": "9.0"},
            {"id": "zsh", "version": "5.9"},
        ]}});
        let d = diff(&old, &new, 100);
        assert_eq!(
            d.changes,
            vec![
                FactChange {
                    path: "software.installed[curl]".into(),
                    kind: ChangeKind::Removed,
                    old: None,
                    new: None
                },
                FactChange {
                    path: "software.installed[bash].version".into(),
                    kind: ChangeKind::Changed,
                    old: Some(json!("5.1")),
                    new: Some(json!("5.2"))
                },
                FactChange {
                    path: "software.installed[zsh]".into(),
                    kind: ChangeKind::Added,
                    old: None,
                    new: None
                },
            ]
        );
    }

    #[test]
    fn sets_appear_and_disappear() {
        let old = json!({"os": {"family": "linux"}});
        let new = json!({"hardware": {"cpu_cores": 4}});
        let d = diff(&old, &new, 100);
        let kinds: Vec<(&str, ChangeKind)> = d
            .changes
            .iter()
            .map(|c| (c.path.as_str(), c.kind))
            .collect();
        assert_eq!(
            kinds,
            vec![("hardware", ChangeKind::Added), ("os", ChangeKind::Removed)]
        );
    }

    #[test]
    fn plain_lists_change_as_a_whole() {
        let old = json!({"network": {"interfaces": [{"id": "eth0", "addresses": ["10.0.0.1"]}]}});
        let new = json!({"network": {"interfaces": [{"id": "eth0", "addresses": ["10.0.0.2"]}]}});
        let d = diff(&old, &new, 100);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].path, "network.interfaces[eth0].addresses");
        assert_eq!(d.changes[0].old, Some(json!(["10.0.0.1"])));
        assert_eq!(d.changes[0].new, Some(json!(["10.0.0.2"])));
    }

    #[test]
    fn a_first_record_in_an_empty_list_is_one_addition() {
        let old = json!({"storage": {"volumes": []}});
        let new = json!({"storage": {"volumes": [{"id": "/", "size_bytes": 1}]}});
        let d = diff(&old, &new, 100);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].path, "storage.volumes[/]");
        assert_eq!(d.changes[0].kind, ChangeKind::Added);
    }

    #[test]
    fn duplicate_ids_fall_back_to_whole_list_comparison() {
        let old = json!({"x": [{"id": "a"}, {"id": "a"}]});
        let new = json!({"x": [{"id": "a"}]});
        let d = diff(&old, &new, 100);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].path, "x");
        assert_eq!(d.changes[0].kind, ChangeKind::Changed);
        // Lists of objects are not copied into the change.
        assert!(d.changes[0].old.is_none());
    }

    #[test]
    fn changes_beyond_the_cap_are_counted() {
        let old = json!({"s": {"l": []}});
        let records: Vec<Value> = (0..10).map(|i| json!({"id": format!("r{i}")})).collect();
        let new = json!({"s": {"l": records}});
        let d = diff(&old, &new, 3);
        assert_eq!(d.changes.len(), 3);
        assert_eq!(d.truncated, 7);
    }

    #[test]
    fn long_strings_are_clipped() {
        let old = json!({"a": "x"});
        let new = json!({"a": "y".repeat(500)});
        let d = diff(&old, &new, 10);
        let shown = d.changes[0].new.as_ref().unwrap().as_str().unwrap();
        assert_eq!(shown.chars().count(), MAX_SHOWN_STRING + 1);
    }
}
