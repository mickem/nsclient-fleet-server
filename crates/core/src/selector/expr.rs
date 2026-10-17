use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};

use crate::facts::{valid_source, AGENT_SOURCE};

use super::path::matching;
use super::{
    scalar_text, FactPath, HostTags, SourceFilter, MAX_FACT_PATH_LEN, MAX_KEY_LEN, MAX_VALUE_LEN,
};

const MAX_NODES: usize = 64;
pub(super) const MAX_DEPTH: usize = 8;
const MAX_IN_VALUES: usize = 64;

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

fn check_key(key: &str) -> Result<(), SelectorError> {
    if key.is_empty() {
        return Err(SelectorError::EmptyKey);
    }
    if key.len() > MAX_KEY_LEN {
        return Err(SelectorError::KeyTooLong);
    }
    Ok(())
}
