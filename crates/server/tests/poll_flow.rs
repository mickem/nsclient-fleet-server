mod common;

use common::{signup_login, start, TestServer};

use std::collections::BTreeMap;

use fleet_storage::Db;

/// A well-formed applied_state_hash. The server requires 64 hex characters — it is a
/// SHA-256 and nothing else is meaningful — so tests cannot use a readable placeholder.
const TEST_HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

async fn enroll_a_host(s: &TestServer) -> fleet_agent_sim::EnrolledAgent {
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let token = body["bootstrap_token"].as_str().unwrap().to_string();

    // Trust store rebuild can lag; retry briefly
    let mut last = String::new();
    for _ in 0..20 {
        match fleet_agent_sim::enroll(&s.base_url, &token, Some("alpha"), Some("linux")).await {
            Ok(a) => return a,
            Err(e) => last = format!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("enroll never succeeded: {last}");
}

#[tokio::test]
async fn desired_state_roundtrip_with_304() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let agent = enroll_a_host(&s).await;

    let first = agent.fetch_desired_state(None).await.unwrap();
    let st = first.expect("first call must return 200");
    assert!(!st.state_hash.is_empty());
    assert!(st.next_poll_in_seconds > 0);

    // Skip the poll-interval floor for this test (otherwise we'd wait min_poll_interval).
    let host_id = host_id_from_db(&s.db).await;
    s.agent_limits.forget_last_poll(&host_id);
    let second = agent
        .fetch_desired_state(Some(&st.state_hash))
        .await
        .unwrap();
    assert!(second.is_none(), "matching hash must produce 304");
}

async fn host_id_from_db(db: &Db) -> String {
    sqlx::query_scalar("SELECT id FROM hosts LIMIT 1")
        .fetch_one(&db.read)
        .await
        .unwrap()
}

async fn last_seen(db: &Db, host_id: &str) -> Option<i64> {
    sqlx::query_scalar("SELECT last_seen_at FROM hosts WHERE id = ?")
        .bind(host_id)
        .fetch_one(&db.read)
        .await
        .unwrap()
}

async fn set_last_seen(db: &Db, host_id: &str, at: i64) {
    sqlx::query("UPDATE hosts SET last_seen_at = ? WHERE id = ?")
        .bind(at)
        .bind(host_id)
        .execute(&db.write)
        .await
        .unwrap();
}

/// A host in steady state has nothing to say: it polls, gets a 304, and sends no state
/// report until the configuration changes. That poll has to count as contact — otherwise
/// `last_seen_at` freezes at the last applied change and a fleet polling perfectly on
/// schedule reads `offline`, and then `lost`.
#[tokio::test]
async fn a_304_poll_counts_as_contact() {
    let s = start().await;
    signup_login(&s, "gamma", "gina@example.com").await;
    let agent = enroll_a_host(&s).await;

    let st = agent
        .fetch_desired_state(None)
        .await
        .unwrap()
        .expect("first call must return 200");
    let host_id = host_id_from_db(&s.db).await;

    // Two days of silence: past the lost threshold, so nothing but the poll below can
    // rescue this host.
    let stale = fleet_core::time::now_unix() - 2 * 86_400;
    set_last_seen(&s.db, &host_id, stale).await;

    s.agent_limits.forget_last_poll(&host_id);
    assert!(
        agent
            .fetch_desired_state(Some(&st.state_hash))
            .await
            .unwrap()
            .is_none(),
        "matching hash must produce 304"
    );
    let refreshed = last_seen(&s.db, &host_id).await.expect("last_seen_at set");
    assert!(
        refreshed > stale,
        "a 304 poll must refresh last_seen_at (was {stale}, still {refreshed})"
    );

    // The refresh is skipped while the stored value is still fresh, so a large fleet does
    // not write a row per host per poll.
    let fresh = fleet_core::time::now_unix() - 5;
    set_last_seen(&s.db, &host_id, fresh).await;
    s.agent_limits.forget_last_poll(&host_id);
    agent
        .fetch_desired_state(Some(&st.state_hash))
        .await
        .unwrap();
    assert_eq!(
        last_seen(&s.db, &host_id).await,
        Some(fresh),
        "a last_seen_at inside the refresh window must be left alone"
    );
}

/// The report stores the host's tags — and does *not* touch the tenant's config version.
/// A host's own tags change only its own group membership, so bumping the version
/// invalidated every other host's memoized state for nothing; one host toggling a value at
/// its allowed request rate kept the whole tenant recomputing.
#[tokio::test]
async fn state_report_records_tags_without_disturbing_the_tenant() {
    let s = start().await;
    signup_login(&s, "beta", "bob@example.com").await;
    let agent = enroll_a_host(&s).await;

    let v_before: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();

    let mut tags = BTreeMap::new();
    tags.insert("os".into(), "linux".into());
    tags.insert("sql_server_present".into(), "true".into());
    agent.report_state(Some(TEST_HASH), tags).await.unwrap();

    let v_after: i64 = sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(
        v_after, v_before,
        "a host's own tags must not invalidate the rest of the tenant"
    );

    let row_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM host_tags WHERE source = 'agent'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(row_count, 2);

    // Re-reporting the same tags must NOT bump config_version (idempotent agent reports)
    let mut same = BTreeMap::new();
    same.insert("os".into(), "linux".into());
    same.insert("sql_server_present".into(), "true".into());
    agent.report_state(None, same).await.unwrap();
    let v_after2: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'beta'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(v_after2, v_after, "no-op report must not bump version");

    let stored_hash: Option<String> =
        sqlx::query_scalar("SELECT current_state_hash FROM hosts LIMIT 1")
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(stored_hash.as_deref(), Some(TEST_HASH));
}

/// The agent reports *whether* the host carries configuration of its own that outranks what
/// we send it — never what that configuration is.
///
/// The state that needs proving is the third one. "Never reported" is not "reported no": an
/// agent older than the field says nothing, and reading that as a denial would tell an
/// operator a host is fully fleet-managed on no evidence at all. So the column stays NULL
/// until an agent answers, and a later silent report must not undo an answer already given.
#[tokio::test]
async fn a_host_reports_whether_local_configuration_outranks_the_fleet() {
    let s = start().await;
    signup_login(&s, "gamma", "gwen@example.com").await;
    let agent = enroll_a_host(&s).await;

    let stored = || async {
        sqlx::query_scalar::<_, Option<i64>>("SELECT local_config_present FROM hosts LIMIT 1")
            .fetch_one(&s.db.read)
            .await
            .unwrap()
    };
    // What the operator API says, which is what the UI renders.
    let published = || async {
        let hosts: serde_json::Value = s
            .cookie_jar
            .get(format!("{}/api/hosts", s.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        hosts[0]["local_config_present"].clone()
    };

    assert_eq!(stored().await, None, "unknown until an agent answers");
    assert_eq!(published().await, serde_json::Value::Null);

    // An agent that predates the field: silence changes nothing.
    agent
        .report_state(Some(TEST_HASH), BTreeMap::new())
        .await
        .unwrap();
    assert_eq!(stored().await, None, "an omitted field is not an answer");

    // Reported clean.
    agent
        .report_state_with_local_config(Some(TEST_HASH), BTreeMap::new(), false)
        .await
        .unwrap();
    assert_eq!(stored().await, Some(0));
    assert_eq!(published().await, serde_json::json!(false));

    // Someone edits nsclient.ini on the box.
    agent
        .report_state_with_local_config(Some(TEST_HASH), BTreeMap::new(), true)
        .await
        .unwrap();
    assert_eq!(stored().await, Some(1));
    assert_eq!(published().await, serde_json::json!(true));

    // A report that omits the field must not silently clear what we were told.
    agent
        .report_state(Some(TEST_HASH), BTreeMap::new())
        .await
        .unwrap();
    assert_eq!(
        stored().await,
        Some(1),
        "silence must not retract a reported answer"
    );

    // And it comes back down when the local configuration is removed.
    agent
        .report_state_with_local_config(Some(TEST_HASH), BTreeMap::new(), false)
        .await
        .unwrap();
    assert_eq!(stored().await, Some(0));

    // The flag describes the host; it must not touch the tenant's config version, which
    // exists to invalidate desired state. Nothing about it changes what we send.
    let bumps: i64 = sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'gamma'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(bumps, 0, "local config is not an input to desired state");
}

#[tokio::test]
async fn renew_issues_a_new_cert_and_retires_the_old_one_once_it_is_in_use() {
    let s = start().await;
    signup_login(&s, "gamma", "carol@example.com").await;
    let mut agent = enroll_a_host(&s).await;
    let original_cert = agent.cert_pem.clone();

    let live = || async {
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM host_certs WHERE revoked_at IS NULL")
            .fetch_one(&s.db.read)
            .await
            .unwrap()
    };

    agent.renew().await.unwrap();
    assert_ne!(
        agent.cert_pem, original_cert,
        "cert must change after renew"
    );
    // Both live for now: the server has no way to know the agent received the response
    // until the agent uses what it was sent, and revoking a certificate the agent never
    // got would strand the host.
    assert_eq!(live().await, 2);

    // Heartbeat with the new identity must succeed...
    let _ = agent.heartbeat().await.unwrap();

    // ...and that is the proof that retires the old one. Leaving it live until its own
    // expiry is what kept a key stolen from the host usable for the rest of its 90 days.
    assert_eq!(live().await, 1);
}

#[tokio::test]
async fn poll_interval_floor_returns_429() {
    let s = start().await;
    signup_login(&s, "delta", "dave@example.com").await;
    let agent = enroll_a_host(&s).await;

    // First call records last_poll_at
    let _ = agent.fetch_desired_state(None).await.unwrap();
    // Second call immediately after — under min_poll_interval (free tier = 60s)
    let r = agent.fetch_desired_state(None).await;
    assert!(
        r.is_err(),
        "second call within min_poll_interval must hit the floor (got {r:?})"
    );
}

#[tokio::test]
async fn a_repeat_poll_is_served_from_the_desired_state_cache() {
    let s = start().await;
    signup_login(&s, "cache", "carol@example.com").await;
    let agent = enroll_a_host(&s).await;
    let host_id = host_id_from_db(&s.db).await;

    let (h0, m0) = s.state.desired_state_cache.stats();
    let first = agent.fetch_desired_state(None).await.unwrap();
    let first = first.expect("first poll returns 200");
    let (h1, m1) = s.state.desired_state_cache.stats();
    assert_eq!(m1 - m0, 1, "the first poll must miss and compute");
    assert_eq!(h1 - h0, 0);

    s.agent_limits.forget_last_poll(&host_id);
    let second = agent.fetch_desired_state(None).await.unwrap();
    let second = second.expect("no current_hash sent, so still a 200");
    let (h2, m2) = s.state.desired_state_cache.stats();
    assert_eq!(h2 - h1, 1, "the second poll must be served from cache");
    assert_eq!(m2 - m1, 0, "and must not recompute");

    assert_eq!(
        first.state_hash, second.state_hash,
        "a cached answer must be identical to the computed one"
    );
}

#[tokio::test]
async fn a_config_change_is_never_served_from_a_stale_cache() {
    let s = start().await;
    signup_login(&s, "invalidate", "ivan@example.com").await;
    let agent = enroll_a_host(&s).await;
    let host_id = host_id_from_db(&s.db).await;

    let before = agent
        .fetch_desired_state(None)
        .await
        .unwrap()
        .expect("first poll returns 200");

    // A host override both bumps config_version and changes the merged config, so the new
    // state is observable in the hash rather than only in the cache counters.
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({
            "patch": { "log": { "level": "debug" } },
            "priority": 1000
        }))
        .send()
        .await
        .unwrap();
    assert!(
        r.status().is_success(),
        "override PUT failed: {:?}",
        r.text().await
    );

    let (_, m_before) = s.state.desired_state_cache.stats();
    s.agent_limits.forget_last_poll(&host_id);
    let after = agent
        .fetch_desired_state(None)
        .await
        .unwrap()
        .expect("poll after the change returns 200");
    let (_, m_after) = s.state.desired_state_cache.stats();

    assert_eq!(
        m_after - m_before,
        1,
        "the bumped config_version must force a recompute"
    );
    assert_ne!(
        before.state_hash, after.state_hash,
        "the agent must see the new configuration, not the cached one"
    );
    assert_eq!(
        after.merged_config_json,
        serde_json::json!({ "log": { "level": "debug" } }),
        "override should be layered into the merged config"
    );
}

/// Phase 9 gated the desired-state cache on "if profiling shows the lazy recompute is hot".
/// This is that profile. Ignored by default — it is a measurement, not an assertion, and
/// timings make poor CI gates.
///
///     cargo test --test poll_flow -- --ignored --nocapture cache_speedup
#[tokio::test]
#[ignore = "benchmark: run manually with --nocapture"]
async fn cache_speedup_profile() {
    use std::time::Instant;

    let s = start().await;
    signup_login(&s, "bench", "ben@example.com").await;
    let agent = enroll_a_host(&s).await;
    let _ = agent;
    let host_id = host_id_from_db(&s.db).await;

    // A fleet-shaped tenant: enough groups that selector evaluation is not free, and tags
    // for them to match against.
    for (k, v) in [
        ("role", "sql_server"),
        ("env", "prod"),
        ("os", "windows"),
        ("site", "eu-west"),
    ] {
        s.cookie_jar
            .put(format!("{}/api/hosts/{}/tags/{}", s.base_url, host_id, k))
            .json(&serde_json::json!({ "value": v }))
            .send()
            .await
            .unwrap();
    }
    const GROUPS: usize = 50;
    for i in 0..GROUPS {
        s.cookie_jar
            .post(format!("{}/api/groups", s.base_url))
            .json(&serde_json::json!({
                "name": format!("group-{i:03}"),
                "selector": { "clauses": [{"op": "eq", "key": "role", "value": "sql_server"}] }
            }))
            .send()
            .await
            .unwrap();
    }
    s.cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({ "patch": { "log": { "level": "debug" } } }))
        .send()
        .await
        .unwrap();

    let tenant_id: i64 = sqlx::query_scalar("SELECT id FROM tenants WHERE slug = 'bench'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    let config_version: i64 =
        sqlx::query_scalar("SELECT config_version FROM tenants WHERE slug = 'bench'")
            .fetch_one(&s.db.read)
            .await
            .unwrap();

    const N: usize = 2_000;

    let t0 = Instant::now();
    for _ in 0..N {
        fleet_server::desired_state::compute_uncached(&s.state, tenant_id, &host_id)
            .await
            .unwrap();
    }
    let uncached = t0.elapsed();

    // Warm, then measure steady-state hits.
    fleet_server::desired_state::compute_desired_state_at(
        &s.state,
        tenant_id,
        &host_id,
        config_version,
    )
    .await
    .unwrap();
    let t1 = Instant::now();
    for _ in 0..N {
        fleet_server::desired_state::compute_desired_state_at(
            &s.state,
            tenant_id,
            &host_id,
            config_version,
        )
        .await
        .unwrap();
    }
    let cached = t1.elapsed();

    println!(
        "\ndesired-state, {GROUPS} groups, {N} iterations:\n  \
         uncached {:>9.1?}  ({:>7.1?}/call)\n  \
         cached   {:>9.1?}  ({:>7.1?}/call)\n  \
         speedup  {:.1}x\n",
        uncached,
        uncached / N as u32,
        cached,
        cached / N as u32,
        uncached.as_secs_f64() / cached.as_secs_f64(),
    );
}
