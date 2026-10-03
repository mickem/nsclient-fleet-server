//! Facts import: matching the rows of an operator's file (a CMDB export, a spreadsheet) to
//! the hosts they describe.
//!
//! Each row carries one or more key values, positionally matched to [`KeyTarget`]s — a host
//! field, a tag, or a fact path. A row matches a host when, for *every* key column, one of
//! the host's values for that target equals the row's value once both are put through the
//! same [`Normalize`]. The keys only find the host: the document is then stored by host id,
//! and nothing about the key is kept.
//!
//! The server gathers each host's values per target (that needs the database) and feeds
//! them to a [`KeyIndex`]; everything from there on — normalization, matching, duplicate
//! detection — is here, without I/O.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::selector::{scalar_text, FactPath};

/// Rows one import may carry.
pub const MAX_IMPORT_ROWS: usize = 10_000;
/// Key columns one import may match on.
pub const MAX_IMPORT_KEYS: usize = 4;
/// The prefix every imported source carries: an import named `cmdb` is stored as
/// `import:cmdb`.
pub const IMPORT_SOURCE_PREFIX: &str = "import:";
/// Longest tag key a target may name (the tag routes' own limit).
pub const MAX_TAG_KEY_LEN: usize = 128;

/// Which host field a key column is matched against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostField {
    Id,
    Hostname,
}

/// What one key column is matched against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum KeyTarget {
    Host {
        field: HostField,
    },
    /// Any tag key; manual and agent-reported values both match.
    Tag {
        key: String,
    },
    /// A scalar at `path` in the host's `source` document; a list there matches on each of
    /// its scalar elements.
    Fact {
        source: String,
        path: FactPath,
    },
}

impl KeyTarget {
    /// Why this target cannot be used, if it cannot.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            KeyTarget::Host { .. } => Ok(()),
            KeyTarget::Tag { key } => {
                if key.trim().is_empty() || key.len() > MAX_TAG_KEY_LEN {
                    Err("invalid tag key".into())
                } else {
                    Ok(())
                }
            }
            KeyTarget::Fact { source, .. } => {
                if crate::facts::valid_source(source) {
                    Ok(())
                } else {
                    Err(format!("invalid facts source {source:?}"))
                }
            }
        }
    }
}

/// How both sides of every key comparison are put before comparing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Normalize {
    /// Strip leading and trailing whitespace.
    pub trim: bool,
    /// Compare without regard to case.
    pub case_insensitive: bool,
    /// Compare only the part before the first `.`: `web-01.example.com` as `web-01`.
    pub short_hostname: bool,
}

impl Default for Normalize {
    fn default() -> Self {
        Self {
            trim: true,
            case_insensitive: true,
            short_hostname: false,
        }
    }
}

impl Normalize {
    /// `s` as it is compared. Empty means "no value": an empty cell matches nothing, and
    /// a host's empty value is never matched.
    pub fn apply(&self, s: &str) -> String {
        let mut s = if self.trim { s.trim() } else { s };
        if self.short_hostname {
            if let Some(dot) = s.find('.') {
                s = &s[..dot];
            }
        }
        if self.case_insensitive {
            s.to_lowercase()
        } else {
            s.to_owned()
        }
    }
}

/// The comparable values `path` reaches in `doc`: each scalar as its JSON text (`42`,
/// `true`), and each scalar element of a list. Maps, records and nulls contribute nothing.
pub fn fact_key_values(path: &FactPath, doc: &Value) -> Vec<String> {
    let mut out = Vec::new();
    for v in path.resolve(doc) {
        match v {
            Value::Array(items) => out.extend(items.iter().filter_map(scalar_text)),
            other => out.extend(scalar_text(other)),
        }
    }
    out
}

/// Whether `name` can name an import: the server stores it as `import:<name>`, which must be
/// a valid source; no `:` of its own, and not `agent`.
pub fn valid_import_name(name: &str) -> bool {
    !name.is_empty()
        && name != crate::facts::AGENT_SOURCE
        && !name.contains(':')
        && crate::facts::valid_source(&import_source(name))
}

/// The source an import named `name` is stored under.
pub fn import_source(name: &str) -> String {
    format!("{IMPORT_SOURCE_PREFIX}{name}")
}

/// Every host's normalized values per key target. Hosts are referred to by their index in
/// the caller's host list.
pub struct KeyIndex {
    normalize: Normalize,
    /// Per target: normalized value → hosts holding it, ascending, without repeats.
    targets: Vec<HashMap<String, Vec<usize>>>,
}

impl KeyIndex {
    pub fn new(targets: usize, normalize: Normalize) -> Self {
        Self {
            normalize,
            targets: vec![HashMap::new(); targets],
        }
    }

    /// Record that host `host` has `value` for target `target`.
    pub fn add(&mut self, target: usize, host: usize, value: &str) {
        let v = self.normalize.apply(value);
        if v.is_empty() {
            return;
        }
        let hosts = self.targets[target].entry(v).or_default();
        if let Err(at) = hosts.binary_search(&host) {
            hosts.insert(at, host);
        }
    }

    /// The hosts matching every key of a row, ascending. `keys` is positional, one per
    /// target; an empty or missing one matches nothing.
    pub fn lookup(&self, keys: &[String]) -> Vec<usize> {
        if keys.len() != self.targets.len() || keys.is_empty() {
            return Vec::new();
        }
        let mut result: Option<Vec<usize>> = None;
        for (target, key) in self.targets.iter().zip(keys) {
            let k = self.normalize.apply(key);
            let Some(hosts) = (!k.is_empty()).then(|| target.get(&k)).flatten() else {
                return Vec::new();
            };
            result = Some(match result {
                None => hosts.clone(),
                Some(prev) => prev
                    .into_iter()
                    .filter(|h| hosts.binary_search(h).is_ok())
                    .collect(),
            });
            if result.as_ref().is_some_and(Vec::is_empty) {
                return Vec::new();
            }
        }
        result.unwrap_or_default()
    }
}

/// How a row asks to be matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RowKey<'a> {
    /// By its key values, against the index.
    Keys(&'a [String]),
    /// By an explicit host id the operator picked: `Some` with the host's index if the host
    /// exists, `None` if it does not.
    Host(Option<usize>),
    /// Left out of this import: not matched, and not counted as a duplicate's original.
    Skipped,
}

/// What a row resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolution {
    Matched(usize),
    Ambiguous(Vec<usize>),
    Unmatched,
    /// The same host as the earlier row `of`, which is the one that keeps it.
    Duplicate {
        host: usize,
        of: usize,
    },
    Skipped,
}

/// Resolve every row. Duplicates are detected after explicit overrides are applied: the
/// first row to land on a host keeps it, and every later one is its duplicate.
pub fn resolve_rows(index: &KeyIndex, rows: &[RowKey<'_>]) -> Vec<Resolution> {
    let mut first_row_of: HashMap<usize, usize> = HashMap::new();
    rows.iter()
        .enumerate()
        .map(|(i, row)| {
            let host = match row {
                RowKey::Skipped => return Resolution::Skipped,
                RowKey::Host(None) => return Resolution::Unmatched,
                RowKey::Host(Some(h)) => *h,
                RowKey::Keys(keys) => {
                    let mut hosts = index.lookup(keys);
                    match hosts.len() {
                        0 => return Resolution::Unmatched,
                        1 => hosts.remove(0),
                        _ => return Resolution::Ambiguous(hosts),
                    }
                }
            };
            match first_row_of.get(&host) {
                Some(&of) => Resolution::Duplicate { host, of },
                None => {
                    first_row_of.insert(host, i);
                    Resolution::Matched(host)
                }
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn keys(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn targets_parse_from_the_wire() {
        let t: Vec<KeyTarget> = serde_json::from_value(json!([
            { "kind": "host", "field": "hostname" },
            { "kind": "tag", "key": "site" },
            { "kind": "fact", "source": "agent", "path": "os.name" },
        ]))
        .unwrap();
        assert_eq!(
            t[0],
            KeyTarget::Host {
                field: HostField::Hostname
            }
        );
        assert!(t.iter().all(|t| t.validate().is_ok()));
        assert!(serde_json::from_value::<KeyTarget>(
            json!({ "kind": "fact", "source": "agent", "path": "a..b" })
        )
        .is_err());
        assert!(KeyTarget::Tag { key: " ".into() }.validate().is_err());
        assert!(KeyTarget::Fact {
            source: "Bad".into(),
            path: FactPath::parse("a").unwrap()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn normalization_defaults_and_toggles() {
        let n: Normalize = serde_json::from_value(json!({})).unwrap();
        assert_eq!(n, Normalize::default());
        assert_eq!(n.apply("  Web-01.Example.COM "), "web-01.example.com");
        let short = Normalize {
            short_hostname: true,
            ..n
        };
        assert_eq!(short.apply(" Web-01.Example.COM"), "web-01");
        let exact = Normalize {
            trim: false,
            case_insensitive: false,
            short_hostname: false,
        };
        assert_eq!(exact.apply(" Web "), " Web ");
    }

    #[test]
    fn fact_values_are_scalars_and_list_elements() {
        let doc = json!({
            "a": "x", "n": 42, "b": true, "l": ["p", 1, {"id": "r"}], "m": {"k": 1}, "z": null,
            "recs": [{"id": "r1", "v": "one"}, {"id": "r2", "v": "two"}],
        });
        let at = |p: &str| fact_key_values(&FactPath::parse(p).unwrap(), &doc);
        assert_eq!(at("a"), vec!["x"]);
        assert_eq!(at("n"), vec!["42"]);
        assert_eq!(at("b"), vec!["true"]);
        assert_eq!(at("l"), vec!["p", "1"]);
        assert!(at("m").is_empty());
        assert!(at("z").is_empty());
        assert_eq!(at("recs.v"), vec!["one", "two"]);
        assert!(at("missing").is_empty());
    }

    #[test]
    fn import_names() {
        for ok in ["cmdb", "aws-prod", "x.y_1"] {
            assert!(valid_import_name(ok), "{ok}");
        }
        for bad in ["", "agent", "a:b", "CMDB", "a b", &"a".repeat(60)] {
            assert!(!valid_import_name(bad), "{bad}");
        }
        assert_eq!(import_source("cmdb"), "import:cmdb");
    }

    fn index() -> KeyIndex {
        // Two targets: hostname, and site tag.
        let mut i = KeyIndex::new(2, Normalize::default());
        i.add(0, 0, "web-01");
        i.add(0, 1, "WEB-02");
        i.add(0, 2, "web-02");
        i.add(1, 0, "sto");
        i.add(1, 1, "sto");
        i.add(1, 2, "lon");
        i.add(1, 2, "");
        i
    }

    #[test]
    fn composite_keys_intersect() {
        let i = index();
        assert_eq!(i.lookup(&keys(&["web-01", "STO "])), vec![0]);
        assert_eq!(i.lookup(&keys(&["web-02", "lon"])), vec![2]);
        assert_eq!(i.lookup(&keys(&["web-02", "nyc"])), Vec::<usize>::new());
        // An empty cell matches nothing, even a host with an empty value.
        assert!(i.lookup(&keys(&["web-02", ""])).is_empty());
        // Wrong arity matches nothing.
        assert!(i.lookup(&keys(&["web-02"])).is_empty());
    }

    #[test]
    fn rows_resolve_with_duplicates_after_overrides() {
        let mut i = KeyIndex::new(1, Normalize::default());
        i.add(0, 0, "web-01");
        i.add(0, 1, "web-02");
        i.add(0, 2, "web-02");
        let k = |s: &str| vec![s.to_owned()];
        let (a, b, c, d) = (k("web-01"), k("web-02"), k("nope"), k("web-01"));
        let rows = [
            RowKey::Keys(&a),
            RowKey::Keys(&b),
            RowKey::Keys(&c),
            RowKey::Keys(&d),
            RowKey::Host(Some(0)),
            RowKey::Host(None),
            RowKey::Skipped,
            RowKey::Host(Some(2)),
        ];
        assert_eq!(
            resolve_rows(&i, &rows),
            vec![
                Resolution::Matched(0),
                Resolution::Ambiguous(vec![1, 2]),
                Resolution::Unmatched,
                Resolution::Duplicate { host: 0, of: 0 },
                Resolution::Duplicate { host: 0, of: 0 },
                Resolution::Unmatched,
                Resolution::Skipped,
                Resolution::Matched(2),
            ]
        );
        // A skipped first row leaves the host to the next one.
        let rows = [RowKey::Skipped, RowKey::Keys(&d)];
        assert_eq!(
            resolve_rows(&i, &rows),
            vec![Resolution::Skipped, Resolution::Matched(0)]
        );
    }
}
