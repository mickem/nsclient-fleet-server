//! Restricted selector grammar for group definitions.
//!
//! v1 grammar: top-level was an implicit AND of leaf clauses (`eq`, `in`).
//! v1.1 adds compound nodes `and`, `or`, `not`, and the leaf `exists`. The top-level
//! `clauses: Vec<Expr>` is still an implicit AND, so all previously-stored selectors
//! deserialize unchanged. Whenever a single tree-shaped root is needed (e.g. as the
//! body of a `not`), use the recursive `Expr` enum.
//!
//! Stored as structured JSON, never raw text. UI-built. No code-execution surface.
//!
//! v1.2 adds `source` to every leaf, and it is the security-relevant part of this module.
//!
//! Group membership decides which bundles a host is served, and bundles carry scripts and
//! (in the plain format) secrets. A host reports its own tags, so if agent-reported values
//! can satisfy a selector then a compromised host picks its own groups: it claims
//! `role=sql_server`, joins the SQL group, and downloads that group's bundles. That manual
//! tags cannot be overwritten does not help, because supplementing is enough — a leaf
//! matches if *any* value under the key matches.
//!
//! So a leaf now says which source it will accept, and the default is
//! [`SourceFilter::Manual`]: operator-set facts only. An operator who does want to group on
//! what a host says about itself writes `"source": "agent"` or `"source": "any"`, and in
//! doing so states that hosts may place themselves in that group. Because `Manual` is the
//! serde default, every selector written before this change now means operator-set-only,
//! which is the safe reading of what it already said.
//!
//! v1.3 adds the `fact` leaf, which reads a host's facts documents (see [`crate::facts`])
//! instead of its tags. Tags are flat `key = value`; a facts document is a tree with lists
//! of records in it, so the leaf addresses a value by [`FactPath`] and has a `has` test for
//! what a list or map contains. Which document it reads is named, not filtered: `agent` is
//! the one the host uploads about itself and is host-controlled exactly like an agent tag,
//! while an imported source is not the host's to write.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

use crate::facts::{valid_source, AGENT_SOURCE};

const MAX_NODES: usize = 64;
const MAX_DEPTH: usize = 8;
const MAX_IN_VALUES: usize = 64;

/// Longest fact path a selector will store. Paths nest, so this is a few keys' worth.
pub const MAX_FACT_PATH_LEN: usize = 512;

/// Longest tag key a selector will compare, and therefore the longest one worth storing.
/// Public so the tag write paths enforce the same bound: a key longer than this can never
/// be matched, so accepting one is storing something that cannot be used.
pub const MAX_KEY_LEN: usize = 128;
/// Longest tag value, for the same reason.
pub const MAX_VALUE_LEN: usize = 256;
/// Most tags one host may carry. Selectors cap at 64 clauses, so a host with more tags than
/// this has more than any selector could distinguish; the cap exists so an agent cannot
/// grow a row set nothing bounds.
pub const MAX_TAGS_PER_HOST: usize = 128;

/// Where a stored tag came from. A fact about the row, not a policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TagSource {
    /// Set by an operator, through the console or the API.
    Manual,
    /// Reported by the host about itself. Untrusted: the host may be lying.
    Agent,
}

impl TagSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Agent => "agent",
        }
    }

    /// Parse a `host_tags.source` column. Anything unrecognised reads as `Agent`, the
    /// less-trusted of the two: a row we cannot classify must not be promoted to an
    /// operator's assertion.
    pub fn from_db(s: &str) -> Self {
        match s {
            "manual" => Self::Manual,
            _ => Self::Agent,
        }
    }
}

/// Which sources a selector leaf will accept a value from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SourceFilter {
    /// Operator-set tags only. The default, and what an omitted `source` means — so a
    /// selector stored before this field existed cannot be satisfied by a host's own
    /// claims about itself.
    #[default]
    Manual,
    /// Agent-reported tags only.
    Agent,
    /// Either source. An explicit statement that hosts may put themselves in this group.
    Any,
}

impl SourceFilter {
    fn accepts(self, source: TagSource) -> bool {
        match self {
            Self::Manual => source == TagSource::Manual,
            Self::Agent => source == TagSource::Agent,
            Self::Any => true,
        }
    }

    /// True when the host itself can influence whether a leaf with this filter matches.
    pub fn is_host_controlled(self) -> bool {
        matches!(self, Self::Agent | Self::Any)
    }

    fn is_default(&self) -> bool {
        *self == Self::Manual
    }
}

/// One stored tag value, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagValue {
    pub value: String,
    pub source: TagSource,
}

impl TagValue {
    pub fn manual(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: TagSource::Manual,
        }
    }

    pub fn agent(value: impl Into<String>) -> Self {
        Self {
            value: value.into(),
            source: TagSource::Agent,
        }
    }
}

/// A host's tags, keyed by tag key. A key can hold values from both sources at once, which
/// is exactly why each value carries its own: collapsing them into a plain string list is
/// what made an agent's claim indistinguishable from an operator's.
pub type HostTags = HashMap<String, Vec<TagValue>>;

/// A host's facts documents, keyed by source (`agent`, `import:cmdb`, ...). A source the
/// host has no document from is simply absent, and every `fact` leaf on it is false.
pub type HostFacts = HashMap<String, Value>;

fn agent_facts() -> String {
    AGENT_SOURCE.to_owned()
}

/// What a `fact` leaf checks at the values its path resolves to. A leaf matches when *any*
/// resolved value passes, the same reading as a tag key with several values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "test", rename_all = "lowercase")]
pub enum FactTest {
    /// The path resolves to something other than null.
    Exists,
    /// A scalar at the path equals `value`. Numbers and booleans compare by their JSON
    /// spelling (`16`, `true`), so a selector never has to know a fact's type.
    Eq { value: String },
    /// A scalar at the path is one of `values`.
    In { values: Vec<String> },
    /// A list at the path contains `value` — as a scalar element, or as the `id` of a
    /// record — or a map at the path has `value` as a key. The question a list of installed
    /// packages or running services is asked.
    Has { value: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Expr {
    /// A test on a host's facts document rather than its tags.
    Fact {
        /// The document read: [`AGENT_SOURCE`] (the default) or an imported source.
        #[serde(default = "agent_facts")]
        facts: String,
        /// A [`FactPath`], e.g. `os.family` or `software.installed[bash].version`. Parsed
        /// once, when the selector is read, and stored parsed: it is resolved per group per
        /// host on every recompute.
        path: FactPath,
        #[serde(flatten)]
        test: FactTest,
    },
    Eq {
        key: String,
        value: String,
        #[serde(default, skip_serializing_if = "SourceFilter::is_default")]
        source: SourceFilter,
    },
    In {
        key: String,
        values: Vec<String>,
        #[serde(default, skip_serializing_if = "SourceFilter::is_default")]
        source: SourceFilter,
    },
    Exists {
        key: String,
        #[serde(default, skip_serializing_if = "SourceFilter::is_default")]
        source: SourceFilter,
    },
    Not {
        expr: Box<Expr>,
    },
    And {
        exprs: Vec<Expr>,
    },
    Or {
        exprs: Vec<Expr>,
    },
}

/// Back-compat alias — v1 callers used `Clause`. New code should prefer `Expr`.
pub type Clause = Expr;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Selector {
    /// Implicit AND of root expressions. Empty = matches everything (v1 convention).
    #[serde(default)]
    pub clauses: Vec<Expr>,
}

#[derive(Debug, thiserror::Error)]
pub enum SelectorError {
    #[error("too many nodes (max {MAX_NODES})")]
    TooManyNodes,
    #[error("nested too deeply (max {MAX_DEPTH})")]
    TooDeep,
    #[error("too many IN values (max {MAX_IN_VALUES})")]
    TooManyInValues,
    #[error("key too long (max {MAX_KEY_LEN})")]
    KeyTooLong,
    #[error("value too long (max {MAX_VALUE_LEN})")]
    ValueTooLong,
    #[error("empty key")]
    EmptyKey,
    #[error("empty compound (and/or with no children)")]
    EmptyCompound,
    #[error("unknown facts source {0:?}")]
    BadFactsSource(String),
    #[error("bad fact path: {0}")]
    BadFactPath(&'static str),
    #[error("invalid JSON: {0}")]
    Json(String),
}

impl Selector {
    pub fn validate(&self) -> Result<(), SelectorError> {
        let mut node_count = 0usize;
        for c in &self.clauses {
            validate_expr(c, 1, &mut node_count)?;
        }
        Ok(())
    }

    pub fn from_json(v: &serde_json::Value) -> Result<Self, SelectorError> {
        let s: Selector =
            serde_json::from_value(v.clone()).map_err(|e| SelectorError::Json(e.to_string()))?;
        s.validate()?;
        Ok(s)
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(self).expect("selector to_value")
    }

    /// A tag leaf matches if at least one value under its key both satisfies the comparison
    /// and comes from a source the leaf accepts; a fact leaf, if at least one value its path
    /// resolves to in that source's document passes its test.
    ///
    /// `facts` only needs the sources [`Selector::fact_sources`] names; callers load just
    /// those, since a document can be a megabyte.
    pub fn matches(&self, tags: &HostTags, facts: &HostFacts) -> bool {
        // Empty selector matches everything (v1 convention; documented).
        if self.clauses.is_empty() {
            return true;
        }
        let host = Host { tags, facts };
        self.clauses.iter().all(|c| eval(c, &host))
    }

    /// The facts sources this selector reads. Empty for a tags-only selector, which is what
    /// lets the evaluation paths skip loading documents entirely.
    pub fn fact_sources(&self) -> BTreeSet<String> {
        fn walk(e: &Expr, out: &mut BTreeSet<String>) {
            match e {
                Expr::Fact { facts, .. } => {
                    out.insert(facts.clone());
                }
                Expr::Not { expr } => walk(expr, out),
                Expr::And { exprs } | Expr::Or { exprs } => exprs.iter().for_each(|c| walk(c, out)),
                Expr::Eq { .. } | Expr::In { .. } | Expr::Exists { .. } => {}
            }
        }
        let mut out = BTreeSet::new();
        self.clauses.iter().for_each(|c| walk(c, &mut out));
        out
    }

    /// True when some leaf accepts agent-reported values — that is, when a host can decide
    /// for itself whether it belongs to this group. Surfaced in the console so an operator
    /// can see which of their groups a compromised host could talk its way into.
    pub fn is_host_controlled(&self) -> bool {
        self.clauses.iter().any(expr_is_host_controlled)
    }
}

fn expr_is_host_controlled(e: &Expr) -> bool {
    match e {
        Expr::Eq { source, .. } | Expr::In { source, .. } | Expr::Exists { source, .. } => {
            source.is_host_controlled()
        }
        // The agent's document is written by the host, so it is as much the host's claim as
        // an agent tag. Other sources are imported by the operator's side.
        Expr::Fact { facts, .. } => facts == AGENT_SOURCE,
        Expr::Not { expr } => expr_is_host_controlled(expr),
        Expr::And { exprs } | Expr::Or { exprs } => exprs.iter().any(expr_is_host_controlled),
    }
}

fn validate_expr(e: &Expr, depth: usize, nodes: &mut usize) -> Result<(), SelectorError> {
    if depth > MAX_DEPTH {
        return Err(SelectorError::TooDeep);
    }
    *nodes += 1;
    if *nodes > MAX_NODES {
        return Err(SelectorError::TooManyNodes);
    }
    match e {
        Expr::Eq { key, value, .. } => {
            check_key(key)?;
            if value.len() > MAX_VALUE_LEN {
                return Err(SelectorError::ValueTooLong);
            }
        }
        Expr::In { key, values, .. } => {
            check_key(key)?;
            if values.len() > MAX_IN_VALUES {
                return Err(SelectorError::TooManyInValues);
            }
            for v in values {
                if v.len() > MAX_VALUE_LEN {
                    return Err(SelectorError::ValueTooLong);
                }
            }
        }
        Expr::Exists { key, .. } => check_key(key)?,
        Expr::Fact { facts, path, test } => {
            if !valid_source(facts) {
                return Err(SelectorError::BadFactsSource(facts.clone()));
            }
            // Parsed and length-checked when deserialized; checked again for a selector
            // built in code.
            if path.as_str().len() > MAX_FACT_PATH_LEN {
                return Err(SelectorError::BadFactPath("too long"));
            }
            match test {
                FactTest::Exists => {}
                FactTest::Eq { value } | FactTest::Has { value } => {
                    if value.len() > MAX_VALUE_LEN {
                        return Err(SelectorError::ValueTooLong);
                    }
                }
                FactTest::In { values } => {
                    if values.len() > MAX_IN_VALUES {
                        return Err(SelectorError::TooManyInValues);
                    }
                    if values.iter().any(|v| v.len() > MAX_VALUE_LEN) {
                        return Err(SelectorError::ValueTooLong);
                    }
                }
            }
        }
        Expr::Not { expr } => validate_expr(expr, depth + 1, nodes)?,
        Expr::And { exprs } | Expr::Or { exprs } => {
            if exprs.is_empty() {
                return Err(SelectorError::EmptyCompound);
            }
            for child in exprs {
                validate_expr(child, depth + 1, nodes)?;
            }
        }
    }
    Ok(())
}

/// Everything a selector is evaluated against.
struct Host<'a> {
    tags: &'a HostTags,
    facts: &'a HostFacts,
}

fn eval(e: &Expr, host: &Host<'_>) -> bool {
    let tags = host.tags;
    match e {
        Expr::Eq { key, value, source } => matching(tags, key, *source).any(|t| &t.value == value),
        Expr::In {
            key,
            values,
            source,
        } => matching(tags, key, *source).any(|t| values.iter().any(|allowed| allowed == &t.value)),
        Expr::Exists { key, source } => matching(tags, key, *source).next().is_some(),
        Expr::Fact { facts, path, test } => {
            let Some(doc) = host.facts.get(facts) else {
                return false;
            };
            path.resolve(doc).into_iter().any(|v| fact_test(test, v))
        }
        Expr::Not { expr } => !eval(expr, host),
        Expr::And { exprs } => exprs.iter().all(|c| eval(c, host)),
        Expr::Or { exprs } => exprs.iter().any(|c| eval(c, host)),
    }
}

fn fact_test(test: &FactTest, v: &Value) -> bool {
    match test {
        FactTest::Exists => !v.is_null(),
        FactTest::Eq { value } => scalar_text(v).is_some_and(|s| s == *value),
        FactTest::In { values } => scalar_text(v).is_some_and(|s| values.contains(&s)),
        FactTest::Has { value } => match v {
            Value::Array(items) => items.iter().any(|item| match item {
                Value::Object(record) => record.get("id").and_then(Value::as_str) == Some(value),
                other => scalar_text(other).is_some_and(|s| s == *value),
            }),
            Value::Object(map) => map.contains_key(value),
            _ => false,
        },
    }
}

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
fn matching<'a>(
    tags: &'a HostTags,
    key: &str,
    source: SourceFilter,
) -> impl Iterator<Item = &'a TagValue> {
    tags.get(key)
        .into_iter()
        .flatten()
        .filter(move |t| source.accepts(t.source))
}

fn check_key(key: &str) -> Result<(), SelectorError> {
    if key.is_empty() {
        return Err(SelectorError::EmptyKey);
    }
    if key.len() > MAX_KEY_LEN {
        return Err(SelectorError::KeyTooLong);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Most of these tests are about tags; they evaluate against a host with no facts.
    trait TagsOnly {
        fn matches_tags(&self, tags: &HostTags) -> bool;
    }

    impl TagsOnly for Selector {
        fn matches_tags(&self, tags: &HostTags) -> bool {
            self.matches(tags, &HostFacts::new())
        }
    }

    /// A host with no tags and `doc` as its agent document.
    fn agent_doc(s: &Selector, doc: Value) -> bool {
        let facts = HostFacts::from([(AGENT_SOURCE.to_owned(), doc)]);
        s.matches(&HostTags::new(), &facts)
    }

    fn fact(path: &str, test: FactTest) -> Selector {
        Selector {
            clauses: vec![Expr::Fact {
                facts: AGENT_SOURCE.into(),
                path: FactPath::parse(path).unwrap(),
                test,
            }],
        }
    }

    fn fact_eq(path: &str, value: &str) -> Selector {
        fact(
            path,
            FactTest::Eq {
                value: value.into(),
            },
        )
    }

    fn fact_has(path: &str, value: &str) -> Selector {
        fact(
            path,
            FactTest::Has {
                value: value.into(),
            },
        )
    }

    fn inventory() -> Value {
        json!({
            "os": {"family": "windows", "version": "2019", "server": true},
            "hardware": {"memory_gb": 16, "cpu_cores": 4},
            "software": {"installed": [
                {"id": "sqlserver", "version": "15.0"},
                {"id": "bash", "version": "5.2"},
            ]},
            "network": {"interfaces": [
                {"id": "eth0", "addresses": ["10.0.0.5", "fe80::1"]},
                {"id": "eth1", "addresses": ["192.168.1.9"]},
            ]},
            "services": {"MSSQLSERVER": {"state": "running"}, "w3svc.x": {"state": "stopped"}},
        })
    }

    // ---- fact leaves ---------------------------------------------------------------

    #[test]
    fn fact_eq_reads_a_nested_scalar() {
        assert!(agent_doc(&fact_eq("os.family", "windows"), inventory()));
        assert!(!agent_doc(&fact_eq("os.family", "linux"), inventory()));
        assert!(!agent_doc(&fact_eq("os.missing", "windows"), inventory()));
    }

    #[test]
    fn numbers_and_booleans_compare_by_their_json_spelling() {
        assert!(agent_doc(&fact_eq("hardware.memory_gb", "16"), inventory()));
        assert!(agent_doc(&fact_eq("os.server", "true"), inventory()));
    }

    #[test]
    fn eq_does_not_look_inside_a_list_or_map() {
        // That is `has`: equality with a whole list would be a guess at what was meant.
        assert!(!agent_doc(
            &fact_eq("network.interfaces.addresses", "10.0.0.5"),
            inventory()
        ));
        assert!(!agent_doc(&fact_eq("os", "windows"), inventory()));
    }

    #[test]
    fn has_finds_a_record_by_id() {
        assert!(agent_doc(
            &fact_has("software.installed", "sqlserver"),
            inventory()
        ));
        assert!(!agent_doc(
            &fact_has("software.installed", "nginx"),
            inventory()
        ));
    }

    #[test]
    fn has_finds_a_scalar_element_through_a_list_of_records() {
        // Any interface: the path fans out over the list of interfaces.
        assert!(agent_doc(
            &fact_has("network.interfaces.addresses", "192.168.1.9"),
            inventory()
        ));
        assert!(!agent_doc(
            &fact_has("network.interfaces.addresses", "10.9.9.9"),
            inventory()
        ));
    }

    #[test]
    fn has_on_a_map_is_a_key_lookup() {
        assert!(agent_doc(&fact_has("services", "MSSQLSERVER"), inventory()));
        assert!(!agent_doc(&fact_has("services", "nginx"), inventory()));
    }

    #[test]
    fn fanning_out_over_records_matches_any_of_them() {
        assert!(agent_doc(
            &fact_eq("software.installed.version", "5.2"),
            inventory()
        ));
    }

    #[test]
    fn an_id_ties_conditions_to_one_record() {
        // bash is 5.2 and sqlserver is 15.0: fanned out, "installed has bash" and "some
        // installed version is 15.0" are both true, but bash's own version is not 15.0.
        assert!(agent_doc(
            &fact_eq("software.installed[bash].version", "5.2"),
            inventory()
        ));
        assert!(!agent_doc(
            &fact_eq("software.installed[bash].version", "15.0"),
            inventory()
        ));
    }

    #[test]
    fn brackets_reach_a_map_key_that_contains_a_dot() {
        assert!(agent_doc(
            &fact_eq("services[w3svc.x].state", "stopped"),
            inventory()
        ));
    }

    #[test]
    fn fact_in_and_exists() {
        let s = fact(
            "os.version",
            FactTest::In {
                values: vec!["2016".into(), "2019".into()],
            },
        );
        assert!(agent_doc(&s, inventory()));
        assert!(agent_doc(
            &fact("software.installed[bash]", FactTest::Exists),
            inventory()
        ));
        assert!(!agent_doc(
            &fact("software.installed[nginx]", FactTest::Exists),
            inventory()
        ));
        assert!(!agent_doc(
            &fact("os.family", FactTest::Exists),
            json!({"os": {"family": null}})
        ));
    }

    #[test]
    fn a_host_without_the_document_matches_no_fact_leaf() {
        let s = fact_eq("os.family", "windows");
        assert!(!s.matches(&HostTags::new(), &HostFacts::new()));
        // ...and NOT of one is true, as for a missing tag.
        let not = Selector {
            clauses: vec![Expr::Not {
                expr: Box::new(s.clauses[0].clone()),
            }],
        };
        assert!(not.matches(&HostTags::new(), &HostFacts::new()));
    }

    #[test]
    fn a_leaf_reads_only_its_own_source() {
        let s = Selector {
            clauses: vec![Expr::Fact {
                facts: "import:cmdb".into(),
                path: FactPath::parse("os.family").unwrap(),
                test: FactTest::Eq {
                    value: "windows".into(),
                },
            }],
        };
        assert!(
            !agent_doc(&s, inventory()),
            "the agent's document is not the import's"
        );
        let facts = HostFacts::from([("import:cmdb".to_owned(), inventory())]);
        assert!(s.matches(&HostTags::new(), &facts));
    }

    #[test]
    fn agent_facts_are_host_controlled_and_imports_are_not() {
        assert!(fact_eq("os.family", "windows").is_host_controlled());
        let imported = Selector {
            clauses: vec![Expr::Fact {
                facts: "import:cmdb".into(),
                path: FactPath::parse("owner").unwrap(),
                test: FactTest::Exists,
            }],
        };
        assert!(!imported.is_host_controlled());
    }

    #[test]
    fn fact_sources_lists_what_to_load() {
        let s = Selector {
            clauses: vec![
                eq("env", "prod"),
                Expr::Not {
                    expr: Box::new(fact_eq("os.family", "linux").clauses.remove(0)),
                },
            ],
        };
        assert_eq!(s.fact_sources(), BTreeSet::from([AGENT_SOURCE.to_owned()]));
        assert!(Selector {
            clauses: vec![eq("env", "prod")]
        }
        .fact_sources()
        .is_empty());
    }

    #[test]
    fn fact_json_shape() {
        let raw = json!({"clauses": [
            {"op": "fact", "path": "software.installed", "test": "has", "value": "bash"},
            {"op": "fact", "facts": "import:cmdb", "path": "owner", "test": "exists"},
            {"op": "fact", "path": "os.version", "test": "in", "values": ["2019", "2022"]},
        ]});
        let s = Selector::from_json(&raw).unwrap();
        // `facts` defaults to the agent's document when omitted.
        assert_eq!(
            s.clauses[0],
            Expr::Fact {
                facts: AGENT_SOURCE.into(),
                path: FactPath::parse("software.installed").unwrap(),
                test: FactTest::Has {
                    value: "bash".into()
                },
            }
        );
        assert_eq!(Selector::from_json(&s.to_json()).unwrap(), s);
    }

    #[test]
    fn bad_fact_leaves_are_refused() {
        for bad in [
            json!({"op": "fact", "path": "", "test": "exists"}),
            json!({"op": "fact", "path": "a..b", "test": "exists"}),
            json!({"op": "fact", "path": "a[x", "test": "exists"}),
            json!({"op": "fact", "path": "a[]", "test": "exists"}),
            json!({"op": "fact", "path": "a[x]b", "test": "exists"}),
            json!({"op": "fact", "path": "a", "test": "regex", "value": "x"}),
            json!({"op": "fact", "path": "a", "test": "eq"}),
            json!({"op": "fact", "facts": "Bad Source", "path": "a", "test": "exists"}),
            json!({"op": "fact", "path": "a".repeat(MAX_FACT_PATH_LEN + 1), "test": "exists"}),
        ] {
            let s = json!({ "clauses": [bad.clone()] });
            assert!(Selector::from_json(&s).is_err(), "{bad} must be refused");
        }
    }

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

    /// Operator-set tags, which is what most of these tests are about.
    fn tags(items: &[(&str, &[&str])]) -> HostTags {
        items
            .iter()
            .map(|(k, vs)| {
                (
                    (*k).to_owned(),
                    vs.iter().map(|s| TagValue::manual(*s)).collect(),
                )
            })
            .collect()
    }

    /// Tags whose source is spelled out per value: `(key, &[(value, source)])`.
    fn sourced(items: &[(&str, &[(&str, TagSource)])]) -> HostTags {
        items
            .iter()
            .map(|(k, vs)| {
                (
                    (*k).to_owned(),
                    vs.iter()
                        .map(|(v, src)| TagValue {
                            value: (*v).to_owned(),
                            source: *src,
                        })
                        .collect(),
                )
            })
            .collect()
    }

    fn eq(key: &str, value: &str) -> Expr {
        Expr::Eq {
            key: key.into(),
            value: value.into(),
            source: SourceFilter::Manual,
        }
    }

    fn eq_from(key: &str, value: &str, source: SourceFilter) -> Expr {
        Expr::Eq {
            key: key.into(),
            value: value.into(),
            source,
        }
    }

    #[test]
    fn empty_selector_matches_everything() {
        let s = Selector { clauses: vec![] };
        assert!(s.matches_tags(&tags(&[])));
        assert!(s.matches_tags(&tags(&[("os", &["linux"])])));
    }

    #[test]
    fn missing_key_never_matches() {
        let s = Selector {
            clauses: vec![eq("os", "linux")],
        };
        assert!(!s.matches_tags(&tags(&[])));
        assert!(!s.matches_tags(&tags(&[("env", &["prod"])])));
    }

    #[test]
    fn eq_matches_when_any_accepted_value_matches() {
        let s = Selector {
            clauses: vec![eq("role", "sql_server")],
        };
        // Two operator-set values under one key disagree; one matches, so the leaf does.
        assert!(s.matches_tags(&tags(&[("role", &["app", "sql_server"])])));
    }

    // ---- source filtering ---------------------------------------------------------

    #[test]
    fn a_selector_without_a_source_ignores_what_the_host_claims() {
        // The finding this field exists for: a compromised host reporting role=sql_server
        // used to join the SQL group and be served its bundles.
        let s = Selector {
            clauses: vec![eq("role", "sql_server")],
        };
        assert!(!s.matches_tags(&sourced(&[("role", &[("sql_server", TagSource::Agent)])])));
        assert!(s.matches_tags(&sourced(&[("role", &[("sql_server", TagSource::Manual)])])));
    }

    #[test]
    fn an_agent_claim_cannot_supplement_a_manual_tag_into_matching() {
        // Manual tags cannot be *overwritten*, but the agent can add a second value under
        // the same key. Under a manual-source leaf that addition is invisible.
        let s = Selector {
            clauses: vec![eq("env", "prod")],
        };
        assert!(!s.matches_tags(&sourced(&[(
            "env",
            &[("dev", TagSource::Manual), ("prod", TagSource::Agent)]
        )])));
    }

    #[test]
    fn agent_source_opts_in_to_host_reported_values() {
        let s = Selector {
            clauses: vec![eq_from("os", "windows", SourceFilter::Agent)],
        };
        assert!(s.matches_tags(&sourced(&[("os", &[("windows", TagSource::Agent)])])));
        // ...and *only* those: an operator-set value is not what this leaf asked for.
        assert!(!s.matches_tags(&sourced(&[("os", &[("windows", TagSource::Manual)])])));
    }

    #[test]
    fn any_source_accepts_either() {
        let s = Selector {
            clauses: vec![eq_from("os", "windows", SourceFilter::Any)],
        };
        assert!(s.matches_tags(&sourced(&[("os", &[("windows", TagSource::Agent)])])));
        assert!(s.matches_tags(&sourced(&[("os", &[("windows", TagSource::Manual)])])));
    }

    #[test]
    fn not_over_an_agent_leaf_is_still_host_controlled() {
        // A host that stops reporting a tag flips a NOT to true, so the inverse is just as
        // much the host's decision as the positive form.
        let s = Selector {
            clauses: vec![Expr::Not {
                expr: Box::new(eq_from("quarantined", "yes", SourceFilter::Agent)),
            }],
        };
        assert!(s.is_host_controlled());
    }

    #[test]
    fn host_controlled_reports_whether_a_host_can_choose_its_own_membership() {
        let manual_only = Selector {
            clauses: vec![eq("role", "sql_server")],
        };
        assert!(!manual_only.is_host_controlled());

        let mixed = Selector {
            clauses: vec![
                eq("env", "prod"),
                eq_from("os", "windows", SourceFilter::Agent),
            ],
        };
        assert!(mixed.is_host_controlled());

        let nested = Selector {
            clauses: vec![Expr::Or {
                exprs: vec![eq("a", "1"), eq_from("b", "2", SourceFilter::Any)],
            }],
        };
        assert!(nested.is_host_controlled());
    }

    #[test]
    fn exists_respects_the_source_filter() {
        let s = Selector {
            clauses: vec![Expr::Exists {
                key: "sql_present".into(),
                source: SourceFilter::Manual,
            }],
        };
        assert!(!s.matches_tags(&sourced(&[("sql_present", &[("true", TagSource::Agent)])])));
        assert!(s.matches_tags(&sourced(&[("sql_present", &[("true", TagSource::Manual)])])));
    }

    #[test]
    fn in_respects_the_source_filter() {
        let s = Selector {
            clauses: vec![Expr::In {
                key: "os".into(),
                values: vec!["linux".into(), "windows".into()],
                source: SourceFilter::Manual,
            }],
        };
        assert!(!s.matches_tags(&sourced(&[("os", &[("linux", TagSource::Agent)])])));
        assert!(s.matches_tags(&sourced(&[("os", &[("linux", TagSource::Manual)])])));
    }

    #[test]
    fn in_clause() {
        let s = Selector {
            clauses: vec![Expr::In {
                key: "os".into(),
                values: vec!["linux".into(), "windows".into()],
                source: SourceFilter::Manual,
            }],
        };
        assert!(s.matches_tags(&tags(&[("os", &["linux"])])));
        assert!(s.matches_tags(&tags(&[("os", &["windows"])])));
        assert!(!s.matches_tags(&tags(&[("os", &["macos"])])));
    }

    #[test]
    fn and_semantics() {
        let s = Selector {
            clauses: vec![eq("os", "windows"), eq("role", "sql_server")],
        };
        assert!(s.matches_tags(&tags(&[("os", &["windows"]), ("role", &["sql_server"]),])));
        assert!(!s.matches_tags(&tags(&[("os", &["windows"])])));
        assert!(!s.matches_tags(&tags(&[("role", &["sql_server"])])));
    }

    #[test]
    fn exists_matches_any_value() {
        let s = Selector {
            clauses: vec![Expr::Exists {
                key: "env".into(),
                source: SourceFilter::Manual,
            }],
        };
        assert!(s.matches_tags(&tags(&[("env", &["prod"])])));
        assert!(s.matches_tags(&tags(&[("env", &["staging"])])));
        assert!(!s.matches_tags(&tags(&[("os", &["linux"])])));
    }

    #[test]
    fn not_inverts() {
        let s = Selector {
            clauses: vec![Expr::Not {
                expr: Box::new(eq("env", "prod")),
            }],
        };
        assert!(s.matches_tags(&tags(&[("env", &["staging"])])));
        assert!(!s.matches_tags(&tags(&[("env", &["prod"])])));
        // Missing tag: !false = true. Useful for "everything except prod".
        assert!(s.matches_tags(&tags(&[])));
    }

    #[test]
    fn or_short_circuits_correctly() {
        let s = Selector {
            clauses: vec![Expr::Or {
                exprs: vec![eq("role", "sql_server"), eq("role", "sql_cluster")],
            }],
        };
        assert!(s.matches_tags(&tags(&[("role", &["sql_server"])])));
        assert!(s.matches_tags(&tags(&[("role", &["sql_cluster"])])));
        assert!(!s.matches_tags(&tags(&[("role", &["web"])])));
    }

    #[test]
    fn nested_compound() {
        // (os=windows) AND (role IN [sql_server, sql_cluster]) AND NOT (env=dev)
        let s = Selector {
            clauses: vec![
                eq("os", "windows"),
                Expr::In {
                    key: "role".into(),
                    values: vec!["sql_server".into(), "sql_cluster".into()],
                    source: SourceFilter::Manual,
                },
                Expr::Not {
                    expr: Box::new(eq("env", "dev")),
                },
            ],
        };
        assert!(s.matches_tags(&tags(&[
            ("os", &["windows"]),
            ("role", &["sql_server"]),
            ("env", &["prod"])
        ])));
        assert!(!s.matches_tags(&tags(&[
            ("os", &["windows"]),
            ("role", &["sql_server"]),
            ("env", &["dev"])
        ])));
    }

    #[test]
    fn v1_json_still_deserializes() {
        // Exactly the wire format produced by v1 — ensure existing rows still load.
        let raw = json!({
            "clauses": [
                {"op": "eq", "key": "os", "value": "windows"},
                {"op": "in", "key": "role", "values": ["sql_server", "sql_cluster"]}
            ]
        });
        let s = Selector::from_json(&raw).unwrap();
        assert_eq!(s.clauses.len(), 2);
        // No `source` in the stored JSON means manual-only — the safe reading of a
        // selector written before hosts could be distinguished from operators.
        assert!(!s.is_host_controlled());
    }

    #[test]
    fn source_is_omitted_when_it_is_the_default() {
        // Keeps stored selectors byte-identical to what v1.1 wrote, so a round trip
        // through the console does not rewrite every row.
        let s = Selector {
            clauses: vec![eq("os", "windows")],
        };
        assert_eq!(
            s.to_json(),
            json!({"clauses": [{"op": "eq", "key": "os", "value": "windows"}]})
        );
    }

    #[test]
    fn source_round_trips_when_it_is_not_the_default() {
        let s = Selector {
            clauses: vec![eq_from("os", "windows", SourceFilter::Agent)],
        };
        let j = s.to_json();
        assert_eq!(
            j,
            json!({"clauses": [
                {"op": "eq", "key": "os", "value": "windows", "source": "agent"}
            ]})
        );
        assert_eq!(Selector::from_json(&j).unwrap(), s);
    }

    #[test]
    fn rejects_an_unknown_source() {
        let bad = json!({"clauses": [
            {"op": "eq", "key": "k", "value": "v", "source": "trusted"}
        ]});
        assert!(Selector::from_json(&bad).is_err());
    }

    #[test]
    fn v11_json_roundtrip() {
        let s = Selector {
            clauses: vec![Expr::Or {
                exprs: vec![
                    Expr::Exists {
                        key: "sql_present".into(),
                        source: SourceFilter::Manual,
                    },
                    Expr::Not {
                        expr: Box::new(eq("env", "dev")),
                    },
                ],
            }],
        };
        let j = s.to_json();
        let back = Selector::from_json(&j).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn rejects_unknown_op() {
        let bad = json!({"clauses": [{"op": "regex", "key": "k", "value": "v"}]});
        assert!(Selector::from_json(&bad).is_err());
    }

    #[test]
    fn rejects_too_many_nodes() {
        let mut s = Selector { clauses: vec![] };
        for i in 0..80 {
            s.clauses.push(eq(&format!("k{i}"), "v"));
        }
        assert!(matches!(s.validate(), Err(SelectorError::TooManyNodes)));
    }

    #[test]
    fn rejects_too_deep() {
        // Build a chain of nested NOTs deeper than MAX_DEPTH.
        let mut e = eq("k", "v");
        for _ in 0..MAX_DEPTH + 2 {
            e = Expr::Not { expr: Box::new(e) };
        }
        let s = Selector { clauses: vec![e] };
        assert!(matches!(s.validate(), Err(SelectorError::TooDeep)));
    }

    #[test]
    fn rejects_empty_compound() {
        let s = Selector {
            clauses: vec![Expr::And { exprs: vec![] }],
        };
        assert!(matches!(s.validate(), Err(SelectorError::EmptyCompound)));
    }

    #[test]
    fn rejects_empty_key() {
        let s = Selector {
            clauses: vec![eq("", "v")],
        };
        assert!(s.validate().is_err());
    }
}
