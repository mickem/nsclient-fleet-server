//! Host facts end to end: the hash exchange on polls and state reports, the upload on a
//! miss, and what the operator API shows afterwards.

mod common;

use common::{enroll_a_host, signup_login, start, TestServer};
use fleet_agent_sim::facts_upload_body;
use fleet_core::facts::{sha256_hex, AGENT_SOURCE, EMPTY_FACTS_HASH};
use fleet_storage::{HostFactsRepo, ReplaceOutcome};

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
            "import:cmdb",
            &sha256_hex(doc.as_bytes()),
            doc,
            None,
            None,
            Some(r#"{"initial":true,"changes":[],"truncated":0}"#),
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
                bad,
                EMPTY_FACTS_HASH,
                "{}",
                None,
                None,
                None,
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
            AGENT_SOURCE,
            &sha256_hex(OS_DOC_2.as_bytes()),
            OS_DOC_2,
            None,
            None,
            None,
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

#[tokio::test]
async fn switching_every_set_off_clears_the_inventory_without_an_upload() {
    let (s, agent, host_id) = setup().await;
    agent
        .upload_facts(facts_upload_body(OS_DOC, "t"))
        .await
        .unwrap();

    // The operator turned everything off: the agent now reports the empty document's hash.
    // It has no reason to upload `{}`, and must not need to.
    let (_, held) = agent.poll_with_facts(None, EMPTY_FACTS_HASH).await.unwrap();
    assert_eq!(
        held.as_deref(),
        Some(EMPTY_FACTS_HASH),
        "answered with the cleared document's hash, so the agent sees no miss"
    );

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
