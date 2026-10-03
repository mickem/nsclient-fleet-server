//! Facts import end to end: resolving rows to hosts by host field, tag and fact, committing
//! the documents, reading them back, pruning and deleting.

mod common;

use common::{signup_login, start, TestServer};
use fleet_core::facts::sha256_hex;
use fleet_storage::{HostFactsRepo, HostRepo, HostTagsRepo, NewFacts};
use serde_json::{json, Value};

struct Fleet {
    s: TestServer,
    tenant_id: i64,
    /// web-01.example.com: tag site=sto (manual), agent facts with a serial and two IPs.
    h1: String,
    /// WEB-02: tag site=sto (agent-reported).
    h2: String,
    /// db-01: tag site=lon.
    h3: String,
    /// db-01 again: a hostname two hosts share.
    h4: String,
}

const AGENT_DOC: &str =
    r#"{"hw":{"serial":"ABC123"},"n":42,"net":{"ips":["10.0.0.1","10.0.0.2"]}}"#;

async fn setup() -> Fleet {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = 'acme'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    let hosts = HostRepo::new(&s.db);
    let mk = |name: &'static str| {
        let hosts = &hosts;
        async move {
            hosts
                .create(tenant_id, Some(name), Some("linux"))
                .await
                .unwrap()
                .id
        }
    };
    let h1 = mk("web-01.example.com").await;
    let h2 = mk("WEB-02").await;
    let h3 = mk("db-01").await;
    let h4 = mk("db-01").await;
    let tags = HostTagsRepo::new(&s.db);
    tags.upsert_manual_tag(tenant_id, &h1, "site", "sto")
        .await
        .unwrap();
    tags.replace_agent_tags(
        tenant_id,
        &h2,
        &[("site".to_owned(), "sto".to_owned())].into(),
    )
    .await
    .unwrap();
    tags.upsert_manual_tag(tenant_id, &h3, "site", "lon")
        .await
        .unwrap();
    HostFactsRepo::new(&s.db)
        .replace(
            tenant_id,
            &h1,
            &NewFacts {
                source: "agent",
                facts_hash: &sha256_hex(AGENT_DOC.as_bytes()),
                facts_json: AGENT_DOC,
                collected_at: None,
                expected_previous: None,
                history: None,
            },
            100,
        )
        .await
        .unwrap();
    Fleet {
        s,
        tenant_id,
        h1,
        h2,
        h3,
        h4,
    }
}

async fn post(s: &TestServer, path: &str, body: &Value) -> (u16, Value) {
    let r = s
        .cookie_jar
        .post(format!("{}{path}", s.base_url))
        .json(body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let text = r.text().await.unwrap();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::String(text)),
    )
}

async fn resolve(s: &TestServer, body: &Value) -> Value {
    let (status, v) = post(s, "/api/facts/import/resolve", body).await;
    assert_eq!(status, 200, "{v}");
    v
}

async fn commit(s: &TestServer, body: &Value) -> (u16, Value) {
    post(s, "/api/facts/import", body).await
}

async fn delete(s: &TestServer, path: &str) -> (u16, String) {
    let r = s
        .cookie_jar
        .delete(format!("{}{path}", s.base_url))
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

async fn get(s: &TestServer, path: &str) -> Value {
    let r = s
        .cookie_jar
        .get(format!("{}{path}", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

fn hostname_key() -> Value {
    json!({ "kind": "host", "field": "hostname" })
}

fn row(key: &str, facts: Value) -> Value {
    json!({ "keys": [key], "facts": facts })
}

fn statuses(v: &Value) -> Vec<String> {
    v["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["status"].as_str().unwrap().to_owned())
        .collect()
}

#[tokio::test]
async fn rows_resolve_by_hostname_with_overrides_and_duplicates() {
    let f = setup().await;
    let v = resolve(
        &f.s,
        &json!({
            "name": "cmdb",
            "keys": [hostname_key()],
            "rows": [
                row("web-01.example.com", json!({})),
                row("web-02", json!({})),
                row("nope", json!({})),
                row("db-01", json!({})),
                row(" WEB-01.EXAMPLE.COM ", json!({})),
                { "keys": ["zzz"], "host_id": f.h3, "facts": {} },
                { "keys": ["web-02"], "host_id": "no-such-host", "facts": {} },
            ],
        }),
    )
    .await;
    assert_eq!(v["source"], "import:cmdb");
    assert_eq!(
        statuses(&v),
        [
            "matched",
            "matched",
            "unmatched",
            "ambiguous",
            "duplicate",
            "matched",
            "unmatched"
        ]
    );
    let rows = &v["rows"];
    assert_eq!(rows[0]["index"], 0);
    assert_eq!(rows[0]["host_id"], f.h1.as_str());
    assert_eq!(rows[0]["hostname"], "web-01.example.com");
    assert_eq!(rows[1]["host_id"], f.h2.as_str());
    let mut amb: Vec<&str> = rows[3]["host_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h.as_str().unwrap())
        .collect();
    amb.sort();
    let mut want = vec![f.h3.as_str(), f.h4.as_str()];
    want.sort();
    assert_eq!(amb, want);
    assert_eq!(rows[4]["host_id"], f.h1.as_str());
    assert_eq!(rows[4]["of"], 0);
    assert_eq!(rows[5]["host_id"], f.h3.as_str());
    assert_eq!(
        v["stats"],
        json!({ "matched": 3, "ambiguous": 1, "unmatched": 2, "duplicate": 1, "skipped": 0 })
    );
    // Only h4 had no row land on it.
    assert_eq!(v["absent_total"], 1);
    assert_eq!(v["absent"][0]["id"], f.h4.as_str());
    assert_eq!(v["absent"][0]["hostname"], "db-01");
    assert_eq!(v["absent"][0]["has_source"], false);
}

#[tokio::test]
async fn rows_resolve_by_tag_and_by_fact() {
    let f = setup().await;
    let by_tag = resolve(
        &f.s,
        &json!({
            "name": "cmdb",
            "keys": [{ "kind": "tag", "key": "site" }],
            "rows": [row("STO", json!({})), row("lon", json!({})), row("nyc", json!({}))],
        }),
    )
    .await;
    // Manual (h1) and agent (h2) tags both count.
    assert_eq!(statuses(&by_tag), ["ambiguous", "matched", "unmatched"]);
    assert_eq!(by_tag["rows"][1]["host_id"], f.h3.as_str());

    let fact = |path: &str| json!({ "kind": "fact", "source": "agent", "path": path });
    for (path, key) in [
        ("hw.serial", "abc123"),
        ("net.ips", "10.0.0.2"),
        ("n", "42"),
    ] {
        let v = resolve(
            &f.s,
            &json!({ "name": "cmdb", "keys": [fact(path)], "rows": [row(key, json!({}))] }),
        )
        .await;
        assert_eq!(statuses(&v), ["matched"], "{path}");
        assert_eq!(v["rows"][0]["host_id"], f.h1.as_str(), "{path}");
    }
    // A map is not a key value.
    let v = resolve(
        &f.s,
        &json!({ "name": "cmdb", "keys": [fact("hw")], "rows": [row("serial", json!({}))] }),
    )
    .await;
    assert_eq!(statuses(&v), ["unmatched"]);
}

#[tokio::test]
async fn composite_keys_must_all_match() {
    let f = setup().await;
    let v = resolve(
        &f.s,
        &json!({
            "name": "cmdb",
            "keys": [{ "kind": "tag", "key": "site" }, hostname_key()],
            "rows": [
                { "keys": ["sto", "web-02"], "facts": {} },
                { "keys": ["lon", "web-02"], "facts": {} },
                { "keys": ["lon", "db-01"], "facts": {} },
            ],
        }),
    )
    .await;
    assert_eq!(statuses(&v), ["matched", "unmatched", "matched"]);
    assert_eq!(v["rows"][0]["host_id"], f.h2.as_str());
    assert_eq!(v["rows"][2]["host_id"], f.h3.as_str());
}

#[tokio::test]
async fn normalization_can_be_tuned() {
    let f = setup().await;
    let body = |normalize: Value, key: &str| {
        json!({
            "name": "cmdb",
            "keys": [hostname_key()],
            "normalize": normalize,
            "rows": [row(key, json!({}))],
        })
    };
    let v = resolve(&f.s, &body(json!({}), "web-01")).await;
    assert_eq!(statuses(&v), ["unmatched"]);
    let v = resolve(
        &f.s,
        &body(json!({ "short_hostname": true }), "WEB-01.corp"),
    )
    .await;
    assert_eq!(statuses(&v), ["matched"]);
    assert_eq!(v["rows"][0]["host_id"], f.h1.as_str());
    let v = resolve(&f.s, &body(json!({ "case_insensitive": false }), "web-02")).await;
    assert_eq!(statuses(&v), ["unmatched"]);
    let v = resolve(&f.s, &body(json!({ "case_insensitive": false }), "WEB-02")).await;
    assert_eq!(statuses(&v), ["matched"]);
    let v = resolve(&f.s, &body(json!({ "trim": false }), " WEB-02")).await;
    assert_eq!(statuses(&v), ["unmatched"]);
}

fn import_body(f: &Fleet, extra: Value) -> Value {
    let mut body = json!({
        "name": "cmdb",
        "keys": [hostname_key()],
        "collected_at": "2026-10-03T10:00:00Z",
        "rows": [
            row("web-01.example.com", json!({ "owner": "ops", "cost": { "center": 42 } })),
            row("web-02", json!({ "owner": "dev" })),
            { "keys": ["db-01"], "host_id": f.h3, "facts": { "owner": "dba" } },
        ],
    });
    for (k, v) in extra.as_object().unwrap() {
        body[k] = v.clone();
    }
    body
}

#[tokio::test]
async fn a_commit_stores_documents_that_read_back_and_select() {
    let f = setup().await;
    let (status, v) = commit(&f.s, &import_body(&f, json!({}))).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(
        v,
        json!({ "source": "import:cmdb", "stored": 3, "unchanged": 0, "skipped": 0,
                "pruned": 0, "failed": 0 })
    );

    let view = get(&f.s, &format!("/api/hosts/{}/facts", f.h1)).await;
    // The agent view is unchanged...
    assert_eq!(view["source"], "agent");
    assert_eq!(view["facts"]["hw"]["serial"], "ABC123");
    // ...and the import sits beside it.
    let others = view["others"].as_array().unwrap();
    assert_eq!(others.len(), 1);
    let o = &others[0];
    assert_eq!(o["source"], "import:cmdb");
    assert_eq!(
        o["facts"],
        json!({ "cost": { "center": 42 }, "owner": "ops" })
    );
    assert_eq!(o["unreadable"], false);
    assert_eq!(o["collected_at"], "2026-10-03T10:00:00Z");
    let stored = r#"{"cost":{"center":42},"owner":"ops"}"#;
    assert_eq!(o["facts_hash"], sha256_hex(stored.as_bytes()));
    assert_eq!(o["size_bytes"], stored.len());
    assert!(o["received_at"].is_i64());
    assert_eq!(o["changes"][0]["initial"], true);
    assert_eq!(o["changes"][0]["source"], "import:cmdb");
    // A host with no import has none.
    let view = get(&f.s, &format!("/api/hosts/{}/facts", f.h4)).await;
    assert_eq!(view["others"], json!([]));

    // The same file again changes nothing.
    let (_, v) = commit(&f.s, &import_body(&f, json!({}))).await;
    assert_eq!(v["stored"], 0);
    assert_eq!(v["unchanged"], 3);

    // The catalog offers the new source.
    let c = get(&f.s, "/api/facts/catalog").await;
    let src = c["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["source"] == "import:cmdb")
        .expect("import:cmdb in the catalog");
    assert_eq!(src["hosts"], 3);

    // A group selector can read it.
    let (status, matched) = post(
        &f.s,
        "/api/groups/preview",
        &json!({ "selector": { "clauses": [
            { "op": "fact", "facts": "import:cmdb", "path": "owner", "test": "eq", "value": "dba" }
        ] } }),
    )
    .await;
    assert_eq!(status, 200, "{matched}");
    let matched = matched.as_array().unwrap();
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0]["id"], f.h3.as_str());

    // An audit entry records it.
    let audit = get(&f.s, "/api/audit?action=facts.").await;
    let entry = audit
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["action"] == "facts.imported")
        .unwrap();
    assert_eq!(entry["target_id"], "import:cmdb");
}

#[tokio::test]
async fn a_commit_with_unresolved_rows_is_refused_unless_they_are_skipped() {
    let f = setup().await;
    let mut body = import_body(&f, json!({}));
    body["rows"]
        .as_array_mut()
        .unwrap()
        .push(row("db-01", json!({ "x": 1 })));
    body["rows"]
        .as_array_mut()
        .unwrap()
        .push(row("nope", json!({ "x": 1 })));
    body["rows"]
        .as_array_mut()
        .unwrap()
        .push(row("WEB-02", json!({ "x": 1 })));
    let (status, v) = commit(&f.s, &body).await;
    assert_eq!(status, 409, "{v}");
    assert_eq!(v["error"], "unresolved rows");
    assert_eq!(statuses(&v), ["ambiguous", "unmatched", "duplicate"]);
    assert_eq!(v["rows"][0]["index"], 3);
    assert_eq!(v["rows"][2]["of"], 1);
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_facts WHERE source != 'agent'")
        .fetch_one(&f.s.db.read)
        .await
        .unwrap();
    assert_eq!(n, 0, "nothing written");

    // Skipping row 1 makes row 5 the one that holds web-02.
    body["skip"] = json!([1, 3, 4]);
    let (status, v) = commit(&f.s, &body).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["stored"], 3);
    assert_eq!(v["skipped"], 3);
    let view = get(&f.s, &format!("/api/hosts/{}/facts", f.h2)).await;
    assert_eq!(view["others"][0]["facts"], json!({ "x": 1 }));

    // An out-of-range skip is a bad request.
    body["skip"] = json!([99]);
    assert_eq!(commit(&f.s, &body).await.0, 400);
}

#[tokio::test]
async fn prune_removes_the_source_from_hosts_not_in_the_file() {
    let f = setup().await;
    assert_eq!(commit(&f.s, &import_body(&f, json!({}))).await.0, 200);

    // A second file with only web-01: without prune the others keep theirs.
    let only_h1 = json!({ "rows": [row("web-01.example.com", json!({ "owner": "ops" }))] });
    let v = resolve(&f.s, &import_body(&f, only_h1.clone())).await;
    assert_eq!(v["absent_total"], 3);
    // Hosts holding the source first.
    let absent: Vec<(&str, bool)> = v["absent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| {
            (
                a["id"].as_str().unwrap(),
                a["has_source"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(absent.iter().filter(|(_, held)| *held).count(), 2);
    assert!(absent[0].1 && absent[1].1 && !absent[2].1);
    assert_eq!(absent[2].0, f.h4.as_str());

    let (_, v) = commit(&f.s, &import_body(&f, only_h1.clone())).await;
    assert_eq!(v["pruned"], 0);
    let holding = |s: &TestServer, tenant_id: i64| {
        let db = s.db.clone();
        async move {
            HostFactsRepo::new(&db)
                .hosts_with_source(tenant_id, "import:cmdb")
                .await
                .unwrap()
        }
    };
    assert_eq!(holding(&f.s, f.tenant_id).await.len(), 3);

    let mut pruning = import_body(&f, only_h1);
    pruning["prune"] = json!(true);
    let (status, v) = commit(&f.s, &pruning).await;
    assert_eq!(status, 200, "{v}");
    assert_eq!(v["pruned"], 2);
    assert_eq!(holding(&f.s, f.tenant_id).await, vec![f.h1.clone()]);
    // Their history went with them.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM host_fact_changes WHERE source = 'import:cmdb' AND host_id != ?",
    )
    .bind(&f.h1)
    .fetch_one(&f.s.db.read)
    .await
    .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn sources_are_deleted_per_host_and_tenant_wide() {
    let f = setup().await;
    assert_eq!(commit(&f.s, &import_body(&f, json!({}))).await.0, 200);

    let path = format!("/api/hosts/{}/facts/import:cmdb", f.h2);
    assert_eq!(delete(&f.s, &path).await.0, 204);
    assert_eq!(
        get(&f.s, &format!("/api/hosts/{}/facts", f.h2)).await["others"],
        json!([])
    );
    assert_eq!(delete(&f.s, &path).await.0, 404, "already gone");
    assert_eq!(
        delete(&f.s, "/api/hosts/no-such-host/facts/import:cmdb")
            .await
            .0,
        404
    );
    assert_eq!(
        delete(&f.s, &format!("/api/hosts/{}/facts/agent", f.h1))
            .await
            .0,
        400
    );
    assert_eq!(
        delete(&f.s, &format!("/api/hosts/{}/facts/Bad!", f.h1))
            .await
            .0,
        400
    );

    let (status, body) = delete(&f.s, "/api/facts/sources/import:cmdb").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap(),
        json!({ "deleted": 2 })
    );
    assert_eq!(delete(&f.s, "/api/facts/sources/agent").await.0, 400);
    // The agent's own document is untouched.
    let view = get(&f.s, &format!("/api/hosts/{}/facts", f.h1)).await;
    assert_eq!(view["facts"]["hw"]["serial"], "ABC123");
    assert_eq!(view["others"], json!([]));
    // And the catalog forgets the source at once.
    let c = get(&f.s, "/api/facts/catalog").await;
    assert!(c["sources"]
        .as_array()
        .unwrap()
        .iter()
        .all(|s| s["source"] != "import:cmdb"));

    let audit = get(&f.s, "/api/audit?action=facts.").await;
    let actions: Vec<&str> = audit
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["action"].as_str().unwrap())
        .collect();
    assert!(actions.contains(&"facts.deleted"), "{actions:?}");
    assert!(actions.contains(&"facts.source_deleted"), "{actions:?}");
}

#[tokio::test]
async fn a_role_that_cannot_write_config_is_refused() {
    let f = setup().await;
    assert_eq!(commit(&f.s, &import_body(&f, json!({}))).await.0, 200);
    sqlx::query("UPDATE users SET role = 'view_only'")
        .execute(&f.s.db.write)
        .await
        .unwrap();
    let body = import_body(&f, json!({}));
    assert_eq!(post(&f.s, "/api/facts/import/resolve", &body).await.0, 403);
    assert_eq!(commit(&f.s, &body).await.0, 403);
    assert_eq!(
        delete(&f.s, &format!("/api/hosts/{}/facts/import:cmdb", f.h1))
            .await
            .0,
        403
    );
    assert_eq!(delete(&f.s, "/api/facts/sources/import:cmdb").await.0, 403);
    // Reading still works.
    let view = get(&f.s, &format!("/api/hosts/{}/facts", f.h1)).await;
    assert_eq!(view["others"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn bad_requests_are_refused() {
    let f = setup().await;
    let base = import_body(&f, json!({}));
    let with = |k: &str, v: Value| {
        let mut b = base.clone();
        b[k] = v;
        b
    };
    for bad in [
        with("name", json!("agent")),
        with("name", json!("a:b")),
        with("name", json!("CMDB")),
        with("name", json!("")),
        with("name", json!("a".repeat(58))),
        with("keys", json!([])),
        with("keys", Value::Array(vec![hostname_key(); 5])),
        with("keys", json!([{ "kind": "host", "field": "os" }])),
        with(
            "keys",
            json!([{ "kind": "fact", "source": "agent", "path": "a..b" }]),
        ),
        with("keys", json!([{ "kind": "tag", "key": "" }])),
        with(
            "keys",
            json!([{ "kind": "fact", "source": "Bad", "path": "a" }]),
        ),
        with("rows", json!([])),
        with("rows", json!([row("web-02", json!([1]))])),
        with("rows", json!([{ "keys": ["a", "b"], "facts": {} }])),
        with("rows", json!([{ "keys": [{}], "facts": {} }])),
    ] {
        for path in ["/api/facts/import/resolve", "/api/facts/import"] {
            let (status, v) = post(&f.s, path, &bad).await;
            assert_eq!(status, 400, "{path} {bad} -> {v}");
        }
    }
    // The longest name that fits.
    let ok = with("name", json!("a".repeat(57)));
    assert_eq!(post(&f.s, "/api/facts/import/resolve", &ok).await.0, 200);

    // Not JSON by content type.
    let r =
        f.s.cookie_jar
            .post(format!("{}/api/facts/import", f.s.base_url))
            .header("content-type", "text/plain")
            .body(base.to_string())
            .send()
            .await
            .unwrap();
    assert_eq!(r.status(), 415);

    // A document over the per-document limit.
    let big = "x".repeat(fleet_server::facts::MAX_FACTS_BODY_BYTES);
    let (status, _) = post(
        &f.s,
        "/api/facts/import",
        &with("rows", json!([row("web-02", json!({ "big": big }))])),
    )
    .await;
    assert_eq!(status, 413);
    // ...while a body far above axum's 2 MiB default is accepted.
    let rows: Vec<Value> = (0..3)
        .map(|_| row("web-02", json!({ "pad": "y".repeat(1024 * 1024) })))
        .collect();
    let (status, v) = post(
        &f.s,
        "/api/facts/import/resolve",
        &with("rows", json!(rows)),
    )
    .await;
    assert_eq!(status, 200, "{v}");
}

#[tokio::test]
async fn resolve_honors_skip_as_commit_does() {
    let f = setup().await;
    let body = |skip: Value| {
        json!({
            "name": "cmdb",
            "keys": [hostname_key()],
            "skip": skip,
            "rows": [
                row("web-01.example.com", json!({ "a": 1 })),
                row("web-02", json!({})),
                row("db-01", json!({})),
                row("WEB-01.example.com", json!({ "a": 2 })),
            ],
        })
    };
    let v = resolve(&f.s, &body(json!([]))).await;
    assert_eq!(
        statuses(&v),
        ["matched", "matched", "ambiguous", "duplicate"]
    );

    let v = resolve(&f.s, &body(json!([0, 2]))).await;
    assert_eq!(statuses(&v), ["skipped", "matched", "skipped", "matched"]);
    assert_eq!(v["rows"][0], json!({ "index": 0, "status": "skipped" }));
    assert_eq!(v["rows"][3]["host_id"], f.h1.as_str());
    assert_eq!(
        v["stats"],
        json!({ "matched": 2, "ambiguous": 0, "unmatched": 0, "duplicate": 0, "skipped": 2 })
    );
    // Row 3 still covers web-01; db-01's skipped row covers nothing.
    let mut absent: Vec<&str> = v["absent"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap())
        .collect();
    absent.sort();
    let mut want = vec![f.h3.as_str(), f.h4.as_str()];
    want.sort();
    assert_eq!(absent, want);

    // Skipping row 3 instead: row 0 keeps the host.
    let v = resolve(&f.s, &body(json!([2, 3]))).await;
    assert_eq!(statuses(&v), ["matched", "matched", "skipped", "skipped"]);

    // Commit enforces the same outcome.
    let (status, v) = commit(&f.s, &body(json!([0, 2]))).await;
    assert_eq!(status, 200, "{v}");
    let view = get(&f.s, &format!("/api/hosts/{}/facts", f.h1)).await;
    assert_eq!(view["others"][0]["facts"], json!({ "a": 2 }));
}
