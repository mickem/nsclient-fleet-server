//! Host facts end to end: the hash exchange on polls and state reports, the upload on a
//! miss, and what the operator API shows afterwards.

mod common;

use common::{enroll_a_host, signup_login, start, TestServer};
use fleet_agent_sim::facts_upload_body;
use fleet_core::facts::{sha256_hex, AGENT_SOURCE, EMPTY_FACTS_HASH};
use fleet_storage::{HostFactsRepo, NewFacts, ReplaceOutcome};

const OS_DOC: &str = r#"{"os":{"arch":"x86_64","family":"linux","name":"Ubuntu 24.04"},"storage":{"volumes":[{"device":"/dev/vda","id":"/","size_bytes":270553174016,"type":"fixed"}]}}"#;
const OS_DOC_2: &str = r#"{"os":{"arch":"x86_64","family":"linux","name":"Ubuntu 24.04.1"},"storage":{"volumes":[{"device":"/dev/vda","id":"/","size_bytes":270553174016,"type":"fixed"},{"id":"/data","type":"fixed"}]}}"#;

/// Enroll, on a tier whose request budget a whole test fits in.
async fn setup() -> (TestServer, fleet_agent_sim::EnrolledAgent, String) {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    sqlx::query("UPDATE tenants SET tier = 'enterprise'")
        .execute(&s.db.write)
        .await
        .unwrap();
    let agent = enroll_a_host(&s).await;
    let host_id: String = sqlx::query_scalar("SELECT id FROM hosts LIMIT 1")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    (s, agent, host_id)
}

async fn facts_view(s: &TestServer, host_id: &str) -> serde_json::Value {
    let r = s
        .cookie_jar
        .get(format!("{}/api/hosts/{host_id}/facts", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

#[tokio::test]
async fn a_host_with_nothing_enabled_is_answered_and_never_asked_for_more() {
    let (s, agent, host_id) = setup().await;

    let (_, held) = agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    // `none`: the server does facts and holds nothing. The agent reads that as the empty
    // document, which is what it has, so it uploads nothing.
    assert_eq!(held.as_deref(), Some("none"));

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "nothing_enabled");
    assert!(v["facts"].is_null());
    assert_eq!(v["reported_hash"], EMPTY_FACTS_HASH);
    assert_eq!(v["changes"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn an_agent_without_facts_is_still_told_the_hash_and_shows_not_reported() {
    let (s, agent, host_id) = setup().await;
    // The older poll shape: no facts_hash at all. The header is still sent — it costs the
    // agent nothing to ignore.
    agent.fetch_desired_state(None).await.unwrap();
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "not_reported");
    assert!(v["reported_hash"].is_null());
}

#[tokio::test]
async fn the_document_is_uploaded_once_on_a_miss_and_then_only_the_hash_travels() {
    let (s, agent, host_id) = setup().await;
    let hash = sha256_hex(OS_DOC.as_bytes());

    let (first, held) = agent.poll_with_facts(None, &hash).await.unwrap();
    assert_eq!(
        held.as_deref(),
        Some("none"),
        "a miss: the server holds nothing"
    );
    assert_eq!(facts_view(&s, &host_id).await["status"], "pending");

    let (status, held) = agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(held.as_deref(), Some(hash.as_str()));

    // The next poll — a 304, the steady state — answers with the hash we now hold, so the
    // agent has nothing more to send.
    s.agent_limits.forget_last_poll(&host_id);
    let state_hash = first.unwrap().state_hash;
    let (again, held) = agent
        .poll_with_facts(Some(&state_hash), &hash)
        .await
        .unwrap();
    assert!(again.is_none(), "in sync: 304");
    assert_eq!(held.as_deref(), Some(hash.as_str()));

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "current");
    assert_eq!(v["facts_hash"], hash);
    assert_eq!(v["collected_at"], "2026-09-25T10:00:00Z");
    assert_eq!(v["size_bytes"], OS_DOC.len());
    assert_eq!(v["facts"]["os"]["family"], "linux");
    assert_eq!(v["facts"]["storage"]["volumes"][0]["id"], "/");
    let changes = v["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["initial"], true);

    // Stored verbatim: the bytes still hash to what they were filed under.
    let stored: String = sqlx::query_scalar("SELECT facts_json FROM host_facts WHERE host_id = ?")
        .bind(&host_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(stored, OS_DOC);
}

#[tokio::test]
async fn a_state_report_is_answered_with_the_held_hash_too() {
    let (s, agent, host_id) = setup().await;
    let hash = sha256_hex(OS_DOC.as_bytes());
    let held = agent
        .report_state_with_facts(None, Default::default(), &hash)
        .await
        .unwrap();
    assert_eq!(held.as_deref(), Some("none"));

    agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    let held = agent
        .report_state_with_facts(None, Default::default(), &hash)
        .await
        .unwrap();
    assert_eq!(held.as_deref(), Some(hash.as_str()));
    assert_eq!(facts_view(&s, &host_id).await["status"], "current");
}

#[tokio::test]
async fn a_newer_document_is_diffed_by_record_id() {
    let (s, agent, host_id) = setup().await;
    for doc in [OS_DOC, OS_DOC_2] {
        let (status, _) = agent
            .upload_facts(facts_upload_body(doc, "2026-09-25T10:00:00Z"))
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["facts_hash"], sha256_hex(OS_DOC_2.as_bytes()));
    let changes = v["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 2, "the first document, then one diff");
    let latest = &changes[0];
    assert_eq!(latest["initial"], false);
    let paths: Vec<(&str, &str)> = latest["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["path"].as_str().unwrap(), c["kind"].as_str().unwrap()))
        .collect();
    assert_eq!(
        paths,
        vec![("os.name", "changed"), ("storage.volumes[/data]", "added"),]
    );
    assert_eq!(latest["changes"][0]["old"], "Ubuntu 24.04");
    assert_eq!(latest["changes"][0]["new"], "Ubuntu 24.04.1");
}

#[tokio::test]
async fn a_repeated_upload_changes_nothing() {
    let (s, agent, host_id) = setup().await;
    for _ in 0..2 {
        let (status, _) = agent
            .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
            .await
            .unwrap();
        assert_eq!(status, 200);
    }
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["changes"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn an_agent_with_a_newer_document_reads_as_outdated() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    let newer = sha256_hex(OS_DOC_2.as_bytes());
    let (_, held) = agent.poll_with_facts(None, &newer).await.unwrap();
    assert_eq!(
        held.as_deref(),
        Some(sha256_hex(OS_DOC.as_bytes()).as_str())
    );
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "outdated");
    assert_eq!(v["reported_hash"], newer);
    // Still showing what we have, rather than nothing.
    assert_eq!(v["facts"]["os"]["name"], "Ubuntu 24.04");
}

#[tokio::test]
async fn an_upload_whose_hash_does_not_match_is_refused() {
    let (s, agent, host_id) = setup().await;
    let body = format!(
        "{{\"collected_at\":\"t\",\"facts\":{OS_DOC},\"facts_hash\":\"{}\"}}",
        sha256_hex(b"something else")
    );
    let (status, _) = agent.upload_facts(body).await.unwrap();
    assert_eq!(status, 400);
    let (status, _) = agent.upload_facts("[]".into()).await.unwrap();
    assert_eq!(status, 400);
    let v = facts_view(&s, &host_id).await;
    assert!(v["facts"].is_null());
}

#[tokio::test]
async fn an_oversized_upload_is_refused_as_too_large() {
    let (s, agent, host_id) = setup().await;
    let big = format!(
        "{{\"blob\":{{\"data\":\"{}\"}}}}",
        "x".repeat(fleet_server::facts::MAX_FACTS_BODY_BYTES)
    );
    let (status, _) = agent
        .upload_facts(facts_upload_body(&big, "t"))
        .await
        .unwrap();
    // 413 is what the agent reads as "turn a set off", and does not retry.
    assert_eq!(status, 413);
    assert!(facts_view(&s, &host_id).await["facts"].is_null());
}

#[tokio::test]
async fn facts_of_an_unknown_host_are_not_found() {
    let (s, _agent, _host_id) = setup().await;
    let r = s
        .cookie_jar
        .get(format!("{}/api/hosts/nope/facts", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

async fn tenant_of(s: &TestServer, host_id: &str) -> i64 {
    sqlx::query_scalar("SELECT tenant_id FROM hosts WHERE id = ?")
        .bind(host_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap()
}

/// Store a document under a non-agent source, the way an import will.
async fn store_imported(s: &TestServer, host_id: &str, doc: &str) -> bool {
    let outcome = HostFactsRepo::new(&s.db)
        .replace(
            tenant_of(s, host_id).await,
            host_id,
            &NewFacts {
                source: "import:cmdb",
                facts_hash: &sha256_hex(doc.as_bytes()),
                facts_json: doc,
                collected_at: None,
                expected_previous: None,
                history: Some(r#"{"initial":true,"changes":[],"truncated":0}"#),
            },
            100,
        )
        .await
        .unwrap();
    outcome == ReplaceOutcome::Stored
}

#[tokio::test]
async fn a_source_name_outside_the_charset_is_refused() {
    let (s, _agent, host_id) = setup().await;
    let tenant_id = tenant_of(&s, &host_id).await;
    for bad in ["", "Import", "a b", "../x", &"a".repeat(65)] {
        let r = HostFactsRepo::new(&s.db)
            .replace(
                tenant_id,
                &host_id,
                &NewFacts {
                    source: bad,
                    facts_hash: EMPTY_FACTS_HASH,
                    facts_json: "{}",
                    collected_at: None,
                    expected_previous: None,
                    history: None,
                },
                100,
            )
            .await;
        assert!(r.is_err(), "{bad:?} must be refused");
    }
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_facts")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(n, 0);
}

#[tokio::test]
async fn a_write_that_raced_another_is_refused_as_a_conflict() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    // Diffed against "nothing stored", but a document is stored now.
    let outcome = HostFactsRepo::new(&s.db)
        .replace(
            tenant_of(&s, &host_id).await,
            &host_id,
            &NewFacts {
                source: AGENT_SOURCE,
                facts_hash: &sha256_hex(OS_DOC_2.as_bytes()),
                facts_json: OS_DOC_2,
                collected_at: None,
                // Diffed against "nothing stored" — but a document is stored now.
                expected_previous: None,
                history: None,
            },
            100,
        )
        .await
        .unwrap();
    assert_eq!(outcome, ReplaceOutcome::Conflict);
    assert_eq!(
        facts_view(&s, &host_id).await["facts_hash"],
        sha256_hex(OS_DOC.as_bytes())
    );
}

/// Pretend the agent has reported what it reports now for longer than the grace period.
async fn age_reported_hash(s: &TestServer, host_id: &str) {
    sqlx::query("UPDATE hosts SET facts_reported_at = facts_reported_at - ? WHERE id = ?")
        .bind(fleet_server::facts::EMPTY_CLEAR_GRACE_SECS + 1)
        .bind(host_id)
        .execute(&s.db.write)
        .await
        .unwrap();
}

async fn history_len(s: &TestServer, host_id: &str) -> usize {
    facts_view(s, host_id).await["changes"]
        .as_array()
        .unwrap()
        .len()
}

#[tokio::test]
async fn switching_every_set_off_clears_the_inventory_after_the_grace_period() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();

    // The operator turned everything off: the agent now reports the empty document's hash.
    // The clear is pending, and the answer already says so, so the agent uploads nothing.
    let (_, held) = agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    assert_eq!(held.as_deref(), Some(EMPTY_FACTS_HASH));
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "switched_off");
    assert_eq!(
        v["facts"]["os"]["family"], "linux",
        "kept during the grace period"
    );

    // Still saying so once the grace period is over: the next poll clears it.
    age_reported_hash(&s, &host_id).await;
    s.agent_limits.forget_last_poll(&host_id);
    let (_, held) = agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    assert_eq!(held.as_deref(), Some(EMPTY_FACTS_HASH));

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "nothing_enabled");
    assert_eq!(v["facts"], serde_json::json!({}));
    let latest = &v["changes"][0];
    let removed: Vec<&str> = latest["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["path"].as_str().unwrap())
        .collect();
    assert_eq!(removed, vec!["os", "storage"]);
    assert_eq!(latest["changes"][0]["kind"], "removed");
}

#[tokio::test]
async fn a_brief_empty_report_changes_nothing() {
    let (s, agent, host_id) = setup().await;
    let hash = sha256_hex(OS_DOC.as_bytes());
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    let before = history_len(&s, &host_id).await;

    // An agent that polled before its collectors ran, and even sent `{}`...
    agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    let (status, held) = agent
        .upload_facts(facts_upload_body("{}", "t"))
        .await
        .unwrap();
    assert_eq!(status, 200);
    assert_eq!(held.as_deref(), Some(EMPTY_FACTS_HASH));

    // ...and then came back with its inventory.
    s.agent_limits.forget_last_poll(&host_id);
    let (_, held) = agent.poll_with_facts(None, &hash).await.unwrap();
    assert_eq!(held.as_deref(), Some(hash.as_str()), "nothing to re-upload");

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["status"], "current");
    assert_eq!(v["facts_hash"], hash);
    assert_eq!(
        history_len(&s, &host_id).await,
        before,
        "no removed/added churn"
    );
}

#[tokio::test]
async fn a_failed_clear_is_not_reported_as_cleared() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    age_reported_hash(&s, &host_id).await;
    // The document cannot be replaced: the clear has to fail.
    sqlx::query(
        "CREATE TRIGGER no_facts_update BEFORE UPDATE ON host_facts
         BEGIN SELECT RAISE(ABORT, 'refused'); END",
    )
    .execute(&s.db.write)
    .await
    .unwrap();

    s.agent_limits.forget_last_poll(&host_id);
    let (_, held) = agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    assert_eq!(
        held.as_deref(),
        Some(sha256_hex(OS_DOC.as_bytes()).as_str()),
        "answered with what is actually held"
    );
    assert_eq!(
        facts_view(&s, &host_id).await["facts"]["os"]["family"],
        "linux"
    );
}

#[tokio::test]
async fn a_resent_document_updates_when_it_was_collected() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-25T10:00:00Z"))
        .await
        .unwrap();
    let (status, _) = agent
        .upload_facts(facts_upload_body(OS_DOC, "2026-09-26T10:00:00Z"))
        .await
        .unwrap();
    assert_eq!(status, 200);
    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["collected_at"], "2026-09-26T10:00:00Z");
    assert_eq!(v["changes"].as_array().unwrap().len(), 1, "not a change");
}

#[tokio::test]
async fn another_source_is_kept_apart_from_the_agents_document() {
    let (s, agent, host_id) = setup().await;
    let hash = sha256_hex(OS_DOC.as_bytes());
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    assert!(store_imported(&s, &host_id, r#"{"cmdb":{"owner":"ops"}}"#).await);

    // The hash exchange only ever concerns the agent's document: an import beside it must
    // not read as a miss and send the agent into a re-upload.
    let (_, held) = agent.poll_with_facts(None, &hash).await.unwrap();
    assert_eq!(held.as_deref(), Some(hash.as_str()));

    let v = facts_view(&s, &host_id).await;
    assert_eq!(v["source"], "agent");
    assert_eq!(v["status"], "current");
    assert!(v["facts"].get("cmdb").is_none());
    let changes = v["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["source"], "agent");

    // A new agent document replaces the agent's and leaves the import's alone.
    agent
        .upload_facts(facts_upload_body(OS_DOC_2, "t"))
        .await
        .unwrap();
    let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM host_facts WHERE host_id = ?")
        .bind(&host_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(n, 2);
}

/// A group reading the agent's facts, with a bundle assigned. Returns the group id.
async fn fact_group_with_a_bundle(s: &TestServer, clause: serde_json::Value) -> String {
    let g = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({ "name": "sql-hosts", "selector": { "clauses": [clause] } }))
        .send()
        .await
        .unwrap();
    assert_eq!(g.status(), 201);
    let group_id = g.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    let form = reqwest::multipart::Form::new()
        .text("name", "sql-checks")
        .text("version", "1.0.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(b"sql-bundle".to_vec())
                .file_name("bundle.zip")
                .mime_str("application/zip")
                .unwrap(),
        );
    let b = s
        .cookie_jar
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(b.status(), 200);
    let bundle_id = b.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let a = s
        .cookie_jar
        .post(format!("{}/api/groups/{group_id}/bundles", s.base_url))
        .json(&serde_json::json!({ "bundle_id": bundle_id, "priority": 10 }))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), 204);
    group_id
}

async fn bundles_served(
    s: &TestServer,
    agent: &fleet_agent_sim::EnrolledAgent,
    host_id: &str,
) -> usize {
    s.agent_limits.forget_last_poll(host_id);
    agent
        .fetch_desired_state(None)
        .await
        .unwrap()
        .unwrap()
        .bundles
        .len()
}

async fn preview(s: &TestServer, clause: serde_json::Value) -> Vec<serde_json::Value> {
    let r = s
        .cookie_jar
        .post(format!("{}/api/groups/preview", s.base_url))
        .json(&serde_json::json!({ "selector": { "clauses": [clause] } }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    r.json().await.unwrap()
}

const SQL_DOC: &str =
    r#"{"os":{"family":"windows"},"software":{"installed":[{"id":"sqlserver","version":"15.0"}]}}"#;

#[tokio::test]
async fn a_fact_selector_serves_a_bundle_once_the_document_says_so() {
    let (s, agent, host_id) = setup().await;
    let clause = serde_json::json!(
        { "op": "fact", "path": "software.installed", "test": "has", "value": "sqlserver" }
    );
    fact_group_with_a_bundle(&s, clause.clone()).await;

    assert_eq!(bundles_served(&s, &agent, &host_id).await, 0);
    assert!(preview(&s, clause.clone()).await.is_empty());

    // The upload alone moves the host into the group: no tag, no config change, and the
    // cached desired state computed by the poll above must not survive it.
    agent
        .upload_facts(facts_upload_body(SQL_DOC, "t"))
        .await
        .unwrap();
    assert_eq!(bundles_served(&s, &agent, &host_id).await, 1);
    let matched = preview(&s, clause).await;
    assert_eq!(matched.len(), 1);
    assert_eq!(matched[0]["id"], host_id.as_str());

    // ...and a document that no longer says so moves it out again.
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    assert_eq!(bundles_served(&s, &agent, &host_id).await, 0);
}

#[tokio::test]
async fn a_group_with_a_bad_fact_path_is_refused() {
    let (s, _agent, _host_id) = setup().await;
    let r = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(
            &serde_json::json!({ "name": "bad", "selector": { "clauses": [
            { "op": "fact", "path": "a..b", "test": "exists" }
        ] } }),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
}

#[tokio::test]
async fn the_catalog_lists_what_the_fleet_reports() {
    let (s, agent, _host_id) = setup().await;
    let empty: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/facts/catalog", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    // The agent source is offered before any host has uploaded.
    assert_eq!(empty["sources"][0]["source"], AGENT_SOURCE);
    assert_eq!(empty["sources"][0]["hosts"], 0);

    // The catalog above is cached now; the upload has to be what makes it rebuild.
    agent
        .upload_facts(facts_upload_body(SQL_DOC, "t"))
        .await
        .unwrap();
    let c: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/facts/catalog", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let agent_src = &c["sources"][0];
    assert_eq!(agent_src["hosts"], 1);
    let installed = agent_src["paths"]
        .as_array()
        .unwrap()
        .iter()
        .find(|p| p["path"] == "software.installed")
        .unwrap();
    assert_eq!(installed["kind"], "list");
    assert_eq!(installed["values"][0], serde_json::json!(["sqlserver", 1]));
}

#[tokio::test]
async fn the_catalog_forgets_a_deleted_host_at_once() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    let hosts = || async {
        let c: serde_json::Value = s
            .cookie_jar
            .get(format!("{}/api/facts/catalog", s.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        c["sources"][0]["hosts"].as_i64().unwrap()
    };
    assert_eq!(hosts().await, 1, "and now cached");
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{host_id}", s.base_url))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success());
    assert_eq!(hosts().await, 0, "not served from the cache");
}

#[tokio::test]
async fn deleting_a_host_deletes_its_facts() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();
    // Every source's rows go, not just the agent's.
    assert!(store_imported(&s, &host_id, r#"{"cmdb":{"owner":"ops"}}"#).await);
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{host_id}", s.base_url))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    for table in ["host_facts", "host_fact_changes"] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table}"))
            .fetch_one(&s.db.read)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table}");
    }
}
