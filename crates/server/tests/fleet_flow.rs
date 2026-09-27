//! Phase 9 — fleet convergence harness. Spin 50 agents against a real server, exercise the
//! full Phase 4 + Phase 5 pipeline, assert state lands in the DB.

mod common;

use common::{complete_exchange, start_with, TestServer};

use std::collections::BTreeMap;

const FLEET_SIZE: usize = 50;

async fn signup_login(s: &TestServer) {
    s.cookie_jar
        .post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": "ops@fleet.example.com",
            "tenant_slug": "fleet",
            "tenant_name": "Fleet",
            "turnstile_token": "",
        }))
        .send()
        .await
        .unwrap();

    let tenants = fleet_storage::TenantRepo::new(&s.db);
    let users = fleet_storage::UserRepo::new(&s.db);
    let links = fleet_storage::MagicLinkRepo::new(&s.db);
    let t = tenants.get_by_slug("fleet").await.unwrap().unwrap();
    let u = users
        .find_by_email("ops@fleet.example.com")
        .await
        .unwrap()
        .unwrap();
    let token = "magic-fleet-XXXXXXXX";
    let hash = fleet_core::digest::sha256_hex(token.as_bytes());
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();
    let _ = complete_exchange(&s.cookie_jar, &s.base_url, token).await;

    // Bump tenant to enterprise — free tier caps at 5 hosts.
    sqlx::query("UPDATE tenants SET tier = 'enterprise' WHERE slug = 'fleet'")
        .execute(&s.db.write)
        .await
        .unwrap();
}

#[tokio::test]
async fn fifty_agents_enroll_heartbeat_and_report_state() {
    let s = start_with(|st| {
        // Permissive enrollment quota: fleet bring-up issues 50 tokens in about a second.
        st.enrollment_limits = fleet_server::agent_limits::EnrollmentLimits::new(10_000);
    })
    .await;
    signup_login(&s).await;

    // Step 1: issue 50 bootstrap tokens (one /api/hosts call each).
    let mut tokens: Vec<String> = Vec::with_capacity(FLEET_SIZE);
    for _ in 0..FLEET_SIZE {
        let r = s
            .cookie_jar
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "POST /api/hosts: {:?}", r.text().await);
        let body: serde_json::Value = r.json().await.unwrap();
        tokens.push(body["bootstrap_token"].as_str().unwrap().to_string());
    }
    assert_eq!(tokens.len(), FLEET_SIZE);

    // Step 2: enroll all 50 agents concurrently. The tenant CA was loaded into the trust
    // store at signup, so first-attempt enrollment should succeed.
    let base = s.base_url.clone();
    let enroll_futs = tokens.into_iter().enumerate().map(|(i, tok)| {
        let base = base.clone();
        async move {
            let mut last = String::new();
            for _ in 0..6 {
                match fleet_agent_sim::enroll(
                    &base,
                    &tok,
                    Some(&format!("agent-{i:02}")),
                    Some("linux"),
                )
                .await
                {
                    Ok(a) => return Ok::<_, String>(a),
                    Err(e) => last = format!("{e:?}"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(last)
        }
    });
    let agents: Vec<fleet_agent_sim::EnrolledAgent> = futures::future::join_all(enroll_futs)
        .await
        .into_iter()
        .map(|r| r.expect("enroll failed"))
        .collect();
    assert_eq!(agents.len(), FLEET_SIZE);

    // Step 3: each agent does heartbeat + report a tag, all in parallel. Then we verify
    // state landed in the DB.
    let work = agents.into_iter().enumerate().map(|(i, agent)| async move {
        agent.heartbeat().await.expect("heartbeat");
        let mut tags = BTreeMap::new();
        tags.insert("env".into(), "prod".into());
        tags.insert("agent_index".into(), i.to_string());
        agent
            // A state hash is a SHA-256 in hex and the server now insists on that shape.
            .report_state(Some(&format!("{i:064x}")), tags)
            .await
            .expect("state report");
    });
    futures::future::join_all(work).await;

    // Step 4: assertions on the DB.
    let host_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(host_count, FLEET_SIZE as i64, "all hosts must be enrolled");

    let enrolled: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE enrolled_at IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(enrolled, FLEET_SIZE as i64);

    let last_seen_set: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE last_seen_at IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        last_seen_set, FLEET_SIZE as i64,
        "every host should have heartbeat"
    );

    let state_hash_set: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE current_state_hash IS NOT NULL
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        state_hash_set, FLEET_SIZE as i64,
        "every host reports applied state"
    );

    let agent_tag_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM host_tags WHERE source = 'agent' AND key = 'agent_index'
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(
        agent_tag_count, FLEET_SIZE as i64,
        "every agent's reported tag must be stored"
    );

    // Step 5: audit log captured the enrollments.
    let enroll_audit_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'host.enrolled'
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(enroll_audit_count, FLEET_SIZE as i64);
}

/// Full convergence: a bundle assigned via a selector over agent-reported tags reaches all
/// 50 agents through the real pipeline — report tags → poll desired state → download +
/// verify bundle → report applied hash — and the server ends up seeing every host in sync.
#[tokio::test]
async fn fifty_agents_converge_on_assigned_bundle() {
    let s = start_with(|st| {
        // Permissive enrollment quota: fleet bring-up issues 50 tokens in about a second.
        st.enrollment_limits = fleet_server::agent_limits::EnrollmentLimits::new(10_000);
    })
    .await;
    signup_login(&s).await;

    // Operator: upload a bundle, create a group selecting env=prod, assign the bundle.
    let bundle_bytes: Vec<u8> = b"PK\x03\x04-fake-zip-for-convergence-test".to_vec();
    let form = reqwest::multipart::Form::new()
        .text("name", "conv-bundle")
        .text("version", "1.0.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(bundle_bytes).file_name("conv.zip"),
        );
    let bres = s
        .cookie_jar
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(bres.status(), 200, "upload: {:?}", bres.text().await);
    let bundle: serde_json::Value = bres.json().await.unwrap();

    let gres = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "prod",
            // Agent-sourced on purpose: this test is about fifty agents converging on
            // their own, so the group has to be one they can place themselves in. See
            // `fleet_core::selector` for what that opt-in costs.
            "selector": { "clauses": [
                { "op": "eq", "key": "env", "value": "prod", "source": "agent" }
            ] },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(gres.status(), 201, "group: {:?}", gres.text().await);
    let group: serde_json::Value = gres.json().await.unwrap();

    let ares = s
        .cookie_jar
        .post(format!(
            "{}/api/groups/{}/bundles",
            s.base_url,
            group["id"].as_str().unwrap()
        ))
        .json(&serde_json::json!({ "bundle_id": bundle["id"], "priority": 100 }))
        .send()
        .await
        .unwrap();
    assert_eq!(ares.status(), 204, "assign failed");

    // Issue tokens + enroll the fleet.
    let mut tokens: Vec<String> = Vec::with_capacity(FLEET_SIZE);
    for _ in 0..FLEET_SIZE {
        let r = s
            .cookie_jar
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200);
        let body: serde_json::Value = r.json().await.unwrap();
        tokens.push(body["bootstrap_token"].as_str().unwrap().to_string());
    }

    let base = s.base_url.clone();
    let enroll_futs = tokens.into_iter().enumerate().map(|(i, tok)| {
        let base = base.clone();
        async move {
            let mut last = String::new();
            for _ in 0..6 {
                match fleet_agent_sim::enroll(
                    &base,
                    &tok,
                    Some(&format!("conv-{i:02}")),
                    Some("linux"),
                )
                .await
                {
                    Ok(a) => return Ok::<_, String>(a),
                    Err(e) => last = format!("{e:?}"),
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
            Err(last)
        }
    });
    let agents: Vec<fleet_agent_sim::EnrolledAgent> = futures::future::join_all(enroll_futs)
        .await
        .into_iter()
        .map(|r| r.expect("enroll failed"))
        .collect();

    // Each agent: report the tag that puts it in the group, then poll → download → verify →
    // report applied hash. One poll per agent (the tier's poll-interval floor forbids a
    // rapid second poll; server-side in_sync is asserted via the human API instead).
    let work = agents.iter().map(|agent| async move {
        let mut tags = BTreeMap::new();
        tags.insert("env".to_string(), "prod".to_string());
        agent
            .report_state(None, tags.clone())
            .await
            .expect("tag report");

        let ds = agent
            .fetch_desired_state(None)
            .await
            .expect("poll")
            .expect("expected 200 with new state, got 304");
        assert_eq!(ds.bundles.len(), 1, "bundle must be in desired state");
        let b = &ds.bundles[0];
        let bytes = agent
            .fetch_bundle_verified(
                ds.descriptor(b).expect("descriptor"),
                b["signature"].as_str().unwrap(),
            )
            .await
            .expect("bundle download + sha256 + signature verify");
        assert!(!bytes.is_empty());

        agent
            .report_state(Some(&ds.state_hash), tags)
            .await
            .expect("applied report");
        ds.state_hash
    });
    let hashes: Vec<String> = futures::future::join_all(work).await;

    // Convergence: every agent computed the same desired hash…
    let expected = hashes[0].clone();
    assert!(
        hashes.iter().all(|h| h == &expected),
        "all agents must agree on the state hash"
    );

    // …and the server sees every host in sync with it.
    let synced: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM hosts WHERE current_state_hash = ?
         AND tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
    )
    .bind(&expected)
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(synced, FLEET_SIZE as i64, "every host must converge");

    // The operator-facing views agree: list shows the fleet, detail shows in_sync.
    let hosts: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let hosts = hosts.as_array().unwrap();
    assert_eq!(hosts.len(), FLEET_SIZE);

    let sample_id = hosts[0]["id"].as_str().unwrap();
    let desired: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts/{}/desired", s.base_url, sample_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(desired["in_sync"], serde_json::json!(true));
    assert_eq!(desired["state_hash"].as_str().unwrap(), expected);
    assert_eq!(desired["bundles"].as_array().unwrap().len(), 1);

    // …and the list says so on every row, which is the whole point of the status field: a
    // converged fleet is legible without opening a single host.
    assert!(
        hosts
            .iter()
            .all(|h| h["status"] == serde_json::json!("in_sync")),
        "every converged host must read in_sync in the list: {:?}",
        hosts
            .iter()
            .map(|h| h["status"].clone())
            .collect::<Vec<_>>()
    );

    // An operator unassigns the bundle. Nothing about the hosts changed, but what we would
    // serve them did, so the fleet is behind until each one polls again — and the list has
    // to say that immediately rather than after the agents notice.
    let unassign = s
        .cookie_jar
        .delete(format!(
            "{}/api/groups/{}/bundles/{}",
            s.base_url,
            group["id"].as_str().unwrap(),
            bundle["id"].as_str().unwrap()
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(unassign.status(), 204, "unassign failed");

    let hosts: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        hosts
            .as_array()
            .unwrap()
            .iter()
            .all(|h| h["status"] == serde_json::json!("out_of_sync")),
        "a configuration change must show as out of sync before the agents catch up"
    );

    // Silence outranks the hash, in two sizes. Ageing `last_seen_at` is the only way to
    // reach either without waiting out the real grace periods.
    let age_fleet = |secs: i64| {
        let db = s.db.clone();
        async move {
            let t = fleet_core::time::now_unix() - secs;
            sqlx::query(
                "UPDATE hosts SET last_seen_at = ?, enrolled_at = ?
                 WHERE tenant_id = (SELECT id FROM tenants WHERE slug = 'fleet')",
            )
            .bind(t)
            .bind(t)
            .execute(&db.write)
            .await
            .unwrap();
        }
    };
    let statuses = || async {
        let hosts: serde_json::Value = s
            .cookie_jar
            .get(format!("{}/api/hosts", s.base_url))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        hosts
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["status"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };

    // Thirty hours: past the day-long offline grace, well short of the 48h lost threshold.
    age_fleet(30 * 3_600).await;
    assert!(
        statuses().await.iter().all(|st| st == "offline"),
        "a host that stopped calling home must read offline, not out of sync"
    );

    // Three days: past `host_lost_after_secs` (48h in this server's config), so no longer
    // something to wait out. Deliberately not *exactly* the threshold — the comparison is
    // strict, and a test that lands on the boundary would turn on which second it ran in.
    age_fleet(3 * 86_400).await;
    assert!(
        statuses().await.iter().all(|st| st == "lost"),
        "a host silent past the configured threshold must be told apart from a brief outage"
    );
}
