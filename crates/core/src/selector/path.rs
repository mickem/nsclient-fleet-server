use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{HostTags, SourceFilter, TagValue};

/// Longest fact path a selector will store. Paths nest, so this is a few keys' worth.
pub const MAX_FACT_PATH_LEN: usize = 512;

/// A scalar as the text a selector compares it to. `None` for null, a list or a map: those
/// are what `exists` and `has` are for, and equality with a string would be a guess.
pub fn scalar_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// A dotted path into a facts document: `os.family`, `software.installed[bash].version`.
///
/// Each segment is a key, optionally followed by `[id]`. The facts history spells its paths
/// with [`Self::child`] and [`Self::pick`] (see [`crate::facts::diff`]), so a path copied
/// from a change works as a selector:
///
/// * A key steps into a map. Stepping into a *list* steps into every record in it, so
///   `network.interfaces.addresses` is every interface's addresses, and a test on it passes
///   if any of them does.
/// * `[id]` picks one record out of a list by its `id` — or one entry out of a map by its
///   key, which is also how a key containing a dot is reached. Picking the record first is
///   what ties two conditions to the same record: `software.installed[bash].version`.
///
/// Serialized as the path text; deserializing parses it, so a stored selector with a path
/// that does not parse is refused when read rather than evaluated as never matching.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct FactPath {
    raw: String,
    segments: Vec<Segment>,
}

impl TryFrom<String> for FactPath {
    type Error = String;
    fn try_from(raw: String) -> Result<Self, String> {
        if raw.len() > MAX_FACT_PATH_LEN {
            return Err("fact path too long".into());
        }
        Self::parse(&raw).map_err(|e| format!("bad fact path: {e}"))
    }
}

impl From<FactPath> for String {
    fn from(p: FactPath) -> String {
        p.raw
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    key: String,
    ids: Vec<String>,
}

impl FactPath {
    pub fn parse(path: &str) -> Result<Self, &'static str> {
        if path.is_empty() {
            return Err("empty");
        }
        let mut segments = Vec::new();
        let mut rest = path;
        loop {
            let end = rest.find(['.', '[', ']']).unwrap_or(rest.len());
            let key = &rest[..end];
            if key.is_empty() {
                return Err("empty key");
            }
            rest = &rest[end..];
            let mut ids = Vec::new();
            while let Some(after) = rest.strip_prefix('[') {
                let close = after.find(']').ok_or("unclosed [")?;
                let id = &after[..close];
                if id.is_empty() {
                    return Err("empty [id]");
                }
                ids.push(id.to_owned());
                rest = &after[close + 1..];
            }
            segments.push(Segment {
                key: key.to_owned(),
                ids,
            });
            match rest.strip_prefix('.') {
                Some(r) => rest = r,
                None if rest.is_empty() => break,
                None => return Err("expected . after ]"),
            }
        }
        Ok(Self {
            raw: path.to_owned(),
            segments,
        })
    }

    /// The path as written.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// How to write the path to `key` under the path `parent` (`""` at the top), or `None`
    /// when the grammar has no way to: the one place that knows how [`Self::parse`] reads a
    /// key back.
    ///
    /// A plain key is joined with a dot. A key holding `.`, `[` or `]` is written `[key]`,
    /// which needs a key before it and — being a pick — only reaches a map entry, never a
    /// field of the records a list fans out to (`in_record`): there it would select the
    /// record whose id is `key`. An empty key has no spelling at all, nor does one holding
    /// `]`, and neither does a path longer than a selector may store.
    pub fn child(parent: &str, key: &str, in_record: bool) -> Option<String> {
        if key.is_empty() {
            return None;
        }
        let path = if key.contains(['.', '[', ']']) {
            if parent.is_empty() || in_record || key.contains(']') {
                return None;
            }
            format!("{parent}[{key}]")
        } else if parent.is_empty() {
            key.to_owned()
        } else {
            format!("{parent}.{key}")
        };
        (path.len() <= MAX_FACT_PATH_LEN).then_some(path)
    }

    /// How to write the path to the record whose `id` is `id` in the list at `parent`, or
    /// `None` when the grammar has no way to: the `[id]` [`Self::parse`] reads back. An id
    /// is taken up to the first `]`, so one holding `]` has no spelling, nor does an empty
    /// one, a list at the top (there is none: a document is a map), or a path longer than a
    /// selector may store.
    pub fn pick(parent: &str, id: &str) -> Option<String> {
        if parent.is_empty() || id.is_empty() || id.contains(']') {
            return None;
        }
        let path = format!("{parent}[{id}]");
        (path.len() <= MAX_FACT_PATH_LEN).then_some(path)
    }

    /// Every value this path reaches in `doc`.
    pub fn resolve<'a>(&self, doc: &'a Value) -> Vec<&'a Value> {
        let mut current = vec![doc];
        for seg in &self.segments {
            let mut next = Vec::new();
            for v in current {
                match v {
                    Value::Object(m) => next.extend(m.get(&seg.key)),
                    Value::Array(items) => next.extend(
                        items
                            .iter()
                            .filter_map(|i| i.as_object().and_then(|m| m.get(&seg.key))),
                    ),
                    _ => {}
                }
            }
            for id in &seg.ids {
                next = next.into_iter().flat_map(|v| pick(v, id)).collect();
            }
            current = next;
        }
        current
    }
}

/// `[id]` applied to one value: the matching record of a list, or the entry of a map.
fn pick<'a>(v: &'a Value, id: &str) -> Vec<&'a Value> {
    match v {
        Value::Array(items) => items
            .iter()
            .filter(|i| i.get("id").and_then(Value::as_str) == Some(id))
            .collect(),
        Value::Object(m) => m.get(id).into_iter().collect(),
        _ => Vec::new(),
    }
}

/// The values stored under `key` that `source` is willing to look at.
pub(super) fn matching<'a>(
    tags: &'a HostTags,
    key: &str,
    source: SourceFilter,
) -> impl Iterator<Item = &'a TagValue> {
    tags.get(key)
        .into_iter()
        .flatten()
        .filter(move |t| source.accepts(t.source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_spelled_child_path_reads_back_to_its_key() {
        let doc = json!({
            "os": {"family": "linux"},
            "services": {"a.b": {"state": "x"}},
            "software": {"installed": [{"id": "bash", "version": "5.2", "x.y": 1}]},
        });
        let resolve = |p: &str| FactPath::parse(p).unwrap().resolve(&doc);
        let os = FactPath::child("", "os", false).unwrap();
        let family = FactPath::child(&os, "family", false).unwrap();
        assert_eq!(resolve(&family), vec![&json!("linux")]);
        let dotted = FactPath::child("services", "a.b", false).unwrap();
        assert_eq!(dotted, "services[a.b]");
        assert_eq!(resolve(&format!("{dotted}.state")), vec![&json!("x")]);
        let version = FactPath::child("software.installed", "version", true).unwrap();
        assert_eq!(resolve(&version), vec![&json!("5.2")]);

        assert_eq!(FactPath::child("", "", false), None);
        assert_eq!(
            FactPath::child("", "a.b", false),
            None,
            "brackets need a key before them"
        );
        assert_eq!(FactPath::child("software.installed", "x.y", true), None);
        assert_eq!(FactPath::child("s", "a]b", false), None);
        assert_eq!(
            FactPath::child("s", &"k".repeat(MAX_FACT_PATH_LEN), false),
            None
        );
    }

    #[test]
    fn fact_paths_parse() {
        for ok in [
            "os",
            "os.family",
            "a[b]",
            "a[b].c",
            "a[b][c].d",
            "s.installed[python3.11]",
        ] {
            assert!(FactPath::parse(ok).is_ok(), "{ok}");
        }
    }
}
