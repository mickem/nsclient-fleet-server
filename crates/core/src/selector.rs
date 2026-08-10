//! Restricted selector grammar for group definitions.
//!
//! v1 grammar: top-level was an implicit AND of leaf clauses (`eq`, `in`).
//! v1.1 adds compound nodes `and`, `or`, `not`, and the leaf `exists`. The top-level
//! `clauses: Vec<Expr>` is still an implicit AND, so all previously-stored selectors
//! deserialize unchanged. Whenever a single tree-shaped root is needed (e.g. as the
//! body of a `not`), use the recursive `Expr` enum.
//!
//! Stored as structured JSON, never raw text. UI-built. No code-execution surface.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const MAX_NODES: usize = 64;
const MAX_DEPTH: usize = 8;
const MAX_IN_VALUES: usize = 64;
const MAX_KEY_LEN: usize = 128;
const MAX_VALUE_LEN: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Expr {
    Eq { key: String, value: String },
    In { key: String, values: Vec<String> },
    Exists { key: String },
    Not { expr: Box<Expr> },
    And { exprs: Vec<Expr> },
    Or { exprs: Vec<Expr> },
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

    /// Tags is a map from key → list of values (since manual + agent tags can coexist on the
    /// same key with different sources). A leaf matches if at least one value satisfies it.
    pub fn matches(&self, tags: &HashMap<String, Vec<String>>) -> bool {
        // Empty selector matches everything (v1 convention; documented).
        if self.clauses.is_empty() {
            return true;
        }
        self.clauses.iter().all(|c| eval(c, tags))
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
        Expr::Eq { key, value } => {
            check_key(key)?;
            if value.len() > MAX_VALUE_LEN {
                return Err(SelectorError::ValueTooLong);
            }
        }
        Expr::In { key, values } => {
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
        Expr::Exists { key } => check_key(key)?,
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

fn eval(e: &Expr, tags: &HashMap<String, Vec<String>>) -> bool {
    match e {
        Expr::Eq { key, value } => tags
            .get(key)
            .map(|vs| vs.iter().any(|v| v == value))
            .unwrap_or(false),
        Expr::In { key, values } => tags
            .get(key)
            .map(|vs| vs.iter().any(|v| values.iter().any(|allowed| allowed == v)))
            .unwrap_or(false),
        Expr::Exists { key } => tags.get(key).map(|vs| !vs.is_empty()).unwrap_or(false),
        Expr::Not { expr } => !eval(expr, tags),
        Expr::And { exprs } => exprs.iter().all(|c| eval(c, tags)),
        Expr::Or { exprs } => exprs.iter().any(|c| eval(c, tags)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn tags(items: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        items
            .iter()
            .map(|(k, vs)| {
                (
                    (*k).to_owned(),
                    vs.iter().map(|s| (*s).to_owned()).collect(),
                )
            })
            .collect()
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
            clauses: vec![Expr::Eq {
                key: "os".into(),
                value: "linux".into(),
            }],
        };
        assert!(!s.matches(&tags(&[])));
        assert!(!s.matches(&tags(&[("env", &["prod"])])));
    }

    #[test]
    fn eq_matches_when_any_source_value_matches() {
        let s = Selector {
            clauses: vec![Expr::Eq {
                key: "role".into(),
                value: "sql_server".into(),
            }],
        };
        // Manual + agent disagree, but one matches → match
        assert!(s.matches(&tags(&[("role", &["app", "sql_server"])])));
    }

    #[test]
    fn in_clause() {
        let s = Selector {
            clauses: vec![Expr::In {
                key: "os".into(),
                values: vec!["linux".into(), "windows".into()],
            }],
        };
        assert!(s.matches(&tags(&[("os", &["linux"])])));
        assert!(s.matches(&tags(&[("os", &["windows"])])));
        assert!(!s.matches(&tags(&[("os", &["macos"])])));
    }

    #[test]
    fn and_semantics() {
        let s = Selector {
            clauses: vec![
                Expr::Eq {
                    key: "os".into(),
                    value: "windows".into(),
                },
                Expr::Eq {
                    key: "role".into(),
                    value: "sql_server".into(),
                },
            ],
        };
        assert!(s.matches(&tags(&[("os", &["windows"]), ("role", &["sql_server"]),])));
        assert!(!s.matches(&tags(&[("os", &["windows"])])));
        assert!(!s.matches(&tags(&[("role", &["sql_server"])])));
    }

    #[test]
    fn exists_matches_any_value() {
        let s = Selector {
            clauses: vec![Expr::Exists { key: "env".into() }],
        };
        assert!(s.matches(&tags(&[("env", &["prod"])])));
        assert!(s.matches(&tags(&[("env", &["staging"])])));
        assert!(!s.matches(&tags(&[("os", &["linux"])])));
    }

    #[test]
    fn not_inverts() {
        let s = Selector {
            clauses: vec![Expr::Not {
                expr: Box::new(Expr::Eq {
                    key: "env".into(),
                    value: "prod".into(),
                }),
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
                exprs: vec![
                    Expr::Eq {
                        key: "role".into(),
                        value: "sql_server".into(),
                    },
                    Expr::Eq {
                        key: "role".into(),
                        value: "sql_cluster".into(),
                    },
                ],
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
                Expr::Eq {
                    key: "os".into(),
                    value: "windows".into(),
                },
                Expr::In {
                    key: "role".into(),
                    values: vec!["sql_server".into(), "sql_cluster".into()],
                },
                Expr::Not {
                    expr: Box::new(Expr::Eq {
                        key: "env".into(),
                        value: "dev".into(),
                    }),
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
    }

    #[test]
    fn v11_json_roundtrip() {
        let s = Selector {
            clauses: vec![Expr::Or {
                exprs: vec![
                    Expr::Exists {
                        key: "sql_present".into(),
                    },
                    Expr::Not {
                        expr: Box::new(Expr::Eq {
                            key: "env".into(),
                            value: "dev".into(),
                        }),
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
            s.clauses.push(Expr::Eq {
                key: format!("k{i}"),
                value: "v".into(),
            });
        }
        assert!(matches!(s.validate(), Err(SelectorError::TooManyNodes)));
    }

    #[test]
    fn rejects_too_deep() {
        // Build a chain of nested NOTs deeper than MAX_DEPTH.
        let mut e = Expr::Eq {
            key: "k".into(),
            value: "v".into(),
        };
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
            clauses: vec![Expr::Eq {
                key: "".into(),
                value: "v".into(),
            }],
        };
        assert!(s.validate().is_err());
    }
}
