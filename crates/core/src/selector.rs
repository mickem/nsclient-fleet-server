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

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_NODES: usize = 64;
const MAX_DEPTH: usize = 8;
const MAX_IN_VALUES: usize = 64;

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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Expr {
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

    /// A leaf matches if at least one value under its key both satisfies the comparison and
    /// comes from a source the leaf accepts.
    pub fn matches(&self, tags: &HostTags) -> bool {
        // Empty selector matches everything (v1 convention; documented).
        if self.clauses.is_empty() {
            return true;
        }
        self.clauses.iter().all(|c| eval(c, tags))
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

fn eval(e: &Expr, tags: &HostTags) -> bool {
    match e {
        Expr::Eq { key, value, source } => matching(tags, key, *source).any(|t| &t.value == value),
        Expr::In {
            key,
            values,
            source,
        } => matching(tags, key, *source).any(|t| values.iter().any(|allowed| allowed == &t.value)),
        Expr::Exists { key, source } => matching(tags, key, *source).next().is_some(),
        Expr::Not { expr } => !eval(expr, tags),
        Expr::And { exprs } => exprs.iter().all(|c| eval(c, tags)),
        Expr::Or { exprs } => exprs.iter().any(|c| eval(c, tags)),
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
        assert!(s.matches(&tags(&[])));
        assert!(s.matches(&tags(&[("os", &["linux"])])));
    }

    #[test]
    fn missing_key_never_matches() {
        let s = Selector {
            clauses: vec![eq("os", "linux")],
        };
        assert!(!s.matches(&tags(&[])));
        assert!(!s.matches(&tags(&[("env", &["prod"])])));
    }

    #[test]
    fn eq_matches_when_any_accepted_value_matches() {
        let s = Selector {
            clauses: vec![eq("role", "sql_server")],
        };
        // Two operator-set values under one key disagree; one matches, so the leaf does.
        assert!(s.matches(&tags(&[("role", &["app", "sql_server"])])));
    }

    // ---- source filtering ---------------------------------------------------------

    #[test]
    fn a_selector_without_a_source_ignores_what_the_host_claims() {
        // The finding this field exists for: a compromised host reporting role=sql_server
        // used to join the SQL group and be served its bundles.
        let s = Selector {
            clauses: vec![eq("role", "sql_server")],
        };
        assert!(!s.matches(&sourced(&[("role", &[("sql_server", TagSource::Agent)])])));
        assert!(s.matches(&sourced(&[("role", &[("sql_server", TagSource::Manual)])])));
    }

    #[test]
    fn an_agent_claim_cannot_supplement_a_manual_tag_into_matching() {
        // Manual tags cannot be *overwritten*, but the agent can add a second value under
        // the same key. Under a manual-source leaf that addition is invisible.
        let s = Selector {
            clauses: vec![eq("env", "prod")],
        };
        assert!(!s.matches(&sourced(&[(
            "env",
            &[("dev", TagSource::Manual), ("prod", TagSource::Agent)]
        )])));
    }

    #[test]
    fn agent_source_opts_in_to_host_reported_values() {
        let s = Selector {
            clauses: vec![eq_from("os", "windows", SourceFilter::Agent)],
        };
        assert!(s.matches(&sourced(&[("os", &[("windows", TagSource::Agent)])])));
        // ...and *only* those: an operator-set value is not what this leaf asked for.
        assert!(!s.matches(&sourced(&[("os", &[("windows", TagSource::Manual)])])));
    }

    #[test]
    fn any_source_accepts_either() {
        let s = Selector {
            clauses: vec![eq_from("os", "windows", SourceFilter::Any)],
        };
        assert!(s.matches(&sourced(&[("os", &[("windows", TagSource::Agent)])])));
        assert!(s.matches(&sourced(&[("os", &[("windows", TagSource::Manual)])])));
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
        assert!(!s.matches(&sourced(&[("sql_present", &[("true", TagSource::Agent)])])));
        assert!(s.matches(&sourced(&[("sql_present", &[("true", TagSource::Manual)])])));
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
        assert!(!s.matches(&sourced(&[("os", &[("linux", TagSource::Agent)])])));
        assert!(s.matches(&sourced(&[("os", &[("linux", TagSource::Manual)])])));
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
        assert!(s.matches(&tags(&[("os", &["linux"])])));
        assert!(s.matches(&tags(&[("os", &["windows"])])));
        assert!(!s.matches(&tags(&[("os", &["macos"])])));
    }

    #[test]
    fn and_semantics() {
        let s = Selector {
            clauses: vec![eq("os", "windows"), eq("role", "sql_server")],
        };
        assert!(s.matches(&tags(&[("os", &["windows"]), ("role", &["sql_server"]),])));
        assert!(!s.matches(&tags(&[("os", &["windows"])])));
        assert!(!s.matches(&tags(&[("role", &["sql_server"])])));
    }

    #[test]
    fn exists_matches_any_value() {
        let s = Selector {
            clauses: vec![Expr::Exists {
                key: "env".into(),
                source: SourceFilter::Manual,
            }],
        };
        assert!(s.matches(&tags(&[("env", &["prod"])])));
        assert!(s.matches(&tags(&[("env", &["staging"])])));
        assert!(!s.matches(&tags(&[("os", &["linux"])])));
    }

    #[test]
    fn not_inverts() {
        let s = Selector {
            clauses: vec![Expr::Not {
                expr: Box::new(eq("env", "prod")),
            }],
        };
        assert!(s.matches(&tags(&[("env", &["staging"])])));
        assert!(!s.matches(&tags(&[("env", &["prod"])])));
        // Missing tag: !false = true. Useful for "everything except prod".
        assert!(s.matches(&tags(&[])));
    }

    #[test]
    fn or_short_circuits_correctly() {
        let s = Selector {
            clauses: vec![Expr::Or {
                exprs: vec![eq("role", "sql_server"), eq("role", "sql_cluster")],
            }],
        };
        assert!(s.matches(&tags(&[("role", &["sql_server"])])));
        assert!(s.matches(&tags(&[("role", &["sql_cluster"])])));
        assert!(!s.matches(&tags(&[("role", &["web"])])));
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
        assert!(s.matches(&tags(&[
            ("os", &["windows"]),
            ("role", &["sql_server"]),
            ("env", &["prod"])
        ])));
        assert!(!s.matches(&tags(&[
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
