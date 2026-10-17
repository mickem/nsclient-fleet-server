use super::expr::MAX_DEPTH;
use super::*;
use crate::facts::AGENT_SOURCE;
use serde_json::json;
use serde_json::Value;
use std::collections::BTreeSet;

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
