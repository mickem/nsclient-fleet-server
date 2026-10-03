mod common;

use common::{complete_exchange, start, TestServer};

async fn signup_and_login(s: &TestServer) {
    // Signup creates the tenant + tenant secrets
    s.cookie_jar
        .post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": "alice@example.com",
            "tenant_slug": "acme",
            "tenant_name": "Acme",
            "turnstile_token": ""
        }))
        .send()
        .await
        .unwrap();

    // Send-link is uniform 204; instead, fabricate a magic link directly via repos.
    let tenants = fleet_storage::TenantRepo::new(&s.db);
    let users = fleet_storage::UserRepo::new(&s.db);
    let links = fleet_storage::MagicLinkRepo::new(&s.db);
    let t = tenants.get_by_slug("acme").await.unwrap().unwrap();
    let u = users
        .find_by_email("alice@example.com")
        .await
        .unwrap()
        .unwrap();
    let token = "test-magic-link-XXXXXXXX";
    let hash = fleet_core::digest::sha256_hex(token.as_bytes());
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();

    let r = complete_exchange(&s.cookie_jar, &s.base_url, token).await;
    assert_eq!(r.status(), 303);
}

#[tokio::test]
async fn end_to_end_enrollment_and_heartbeat() {
    let s = start().await;
    signup_and_login(&s).await;

    // POST /api/hosts
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "POST /api/hosts: {:?}", r.text().await);
    let create: serde_json::Value = r.json().await.unwrap();
    let bootstrap_token = create["bootstrap_token"].as_str().unwrap().to_string();

    // Belt-and-braces only: `enroll` now awaits `ensure_tenant_trusted`, so the CA is
    // loaded before the response is sent (see
    // `a_new_tenants_ca_is_trusted_before_enrollment_answers`). The loop stays to absorb
    // unrelated transient startup errors.
    let mut last_err = String::from("not attempted");
    let mut enrolled = None;
    for _ in 0..20 {
        // Force a rebuild
        s.cookie_jar
            .get(format!("{}/healthz", s.base_url))
            .send()
            .await
            .ok();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        match fleet_agent_sim::enroll(&s.base_url, &bootstrap_token, Some("alpha"), Some("linux"))
            .await
        {
            Ok(a) => {
                enrolled = Some(a);
                break;
            }
            Err(e) => last_err = format!("{e:?}"),
        }
    }
    let agent = enrolled.unwrap_or_else(|| panic!("agent enroll failed after retries: {last_err}"));

    // Trust store rebuild after enrollment to load this host's CA into the verifier (no-op
    // here — CA was already in the store from signup — but exercised in real flow).
    s.cookie_jar
        .get(format!("{}/healthz", s.base_url))
        .send()
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // mTLS heartbeat. Capped at 8 attempts so we stay under the per-host 10/min limiter
    // when retries do happen (trust-store rebuild lag) — exhausting the quota would mask
    // the real handshake failure with a misleading 429.
    let mut last_err = String::from("not attempted");
    let mut ok = false;
    for _ in 0..8 {
        match agent.heartbeat().await {
            Ok(_) => {
                ok = true;
                break;
            }
            Err(e) => last_err = format!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(ok, "heartbeat failed: {last_err}");
}

#[tokio::test]
async fn enroll_with_bad_bootstrap_token_rejected() {
    let s = start().await;
    signup_and_login(&s).await;

    let result = fleet_agent_sim::enroll(&s.base_url, "not-a-real-jwt", None, None).await;
    assert!(result.is_err());
}

/// A replayed token used to cost a CA-key decrypt and an ECDSA signature before the nonce
/// burn refused it. It is refused on a read now, and — the part that matters more — the
/// burn and the certificate record are one transaction, so a host can never end up marked
/// enrolled with its one-time token spent and no certificate to show for it.
#[tokio::test]
async fn a_replayed_token_leaves_no_trace_of_a_half_enrollment() {
    let s = start().await;
    signup_and_login(&s).await;

    let create: serde_json::Value = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let host_id = create["host_id"].as_str().unwrap().to_string();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    let mut first = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(a) = fleet_agent_sim::enroll(&s.base_url, &token, Some("once"), None).await {
            first = Some(a);
            break;
        }
    }
    assert!(first.is_some(), "first enrollment should succeed");
    assert_eq!(live_cert_count(&s, &host_id).await, 1);

    // The replay is refused, and leaves exactly one certificate behind — not two, and not
    // an orphaned row from a burn whose record failed.
    assert!(
        fleet_agent_sim::enroll(&s.base_url, &token, Some("twice"), None)
            .await
            .is_err(),
        "a spent token must not enroll again"
    );
    assert_eq!(live_cert_count(&s, &host_id).await, 1);
}

#[tokio::test]
async fn enroll_replay_rejected() {
    let s = start().await;
    signup_and_login(&s).await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let create: serde_json::Value = r.json().await.unwrap();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    // First enroll succeeds (with retries while trust store catches up)
    let mut first = None;
    for _ in 0..20 {
        if let Ok(a) = fleet_agent_sim::enroll(&s.base_url, &token, None, None).await {
            first = Some(a);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(first.is_some());

    // Second enroll with the same token must fail
    let second = fleet_agent_sim::enroll(&s.base_url, &token, None, None).await;
    assert!(second.is_err(), "replay must fail");
}

/// Create a host, enroll an agent for it, and prove the agent is live. Returns the
/// host id, the agent, and nothing else worth carrying — the retry loops absorb
/// trust-store rebuild lag, which is unrelated to what the callers are testing.
async fn enrolled_agent(s: &TestServer, name: &str) -> (String, fleet_agent_sim::EnrolledAgent) {
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let create: serde_json::Value = r.json().await.unwrap();
    let host_id = create["host_id"].as_str().unwrap().to_string();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    let mut agent = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(a) = fleet_agent_sim::enroll(&s.base_url, &token, Some(name), None).await {
            agent = Some(a);
            break;
        }
    }
    let agent = agent.expect("enroll failed");

    let mut alive = false;
    for _ in 0..8 {
        if agent.heartbeat().await.is_ok() {
            alive = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(alive, "agent must be able to heartbeat after enrollment");
    (host_id, agent)
}

async fn live_cert_count(s: &TestServer, host_id: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM host_certs WHERE host_id = ? AND revoked_at IS NULL")
        .bind(host_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap()
}

/// A renewal used to leave the previous certificate active until its own expiry, so a host
/// on schedule held several valid identities at once and a key stolen from it stayed usable
/// for the rest of its 90 days. The old one is now retired — but only once the agent has
/// *used* the new one, which is the proof that the renewal response actually arrived.
#[tokio::test]
async fn renewing_retires_the_certificate_it_replaces() {
    let s = start().await;
    signup_and_login(&s).await;
    let (host_id, agent) = enrolled_agent(&s, "renewer").await;
    let mut agent = agent;

    assert_eq!(live_cert_count(&s, &host_id).await, 1);

    agent.renew().await.expect("renew");

    // Both are live at this instant: the server cannot know the agent received the new
    // certificate until the agent shows it can use it.
    assert_eq!(
        live_cert_count(&s, &host_id).await,
        2,
        "the old cert must survive until the new one is demonstrably in hand"
    );

    // One request on the new certificate, and the old one goes.
    agent.heartbeat().await.expect("heartbeat on renewed cert");
    assert_eq!(
        live_cert_count(&s, &host_id).await,
        1,
        "using the renewed cert must retire the one it replaced"
    );
}

/// The operator lever. Revoking used to have no way to happen at all — `revoked_at` was a
/// column nothing wrote, and the only way to stop a certificate being accepted was to
/// delete the host and lose everything attached to it.
#[tokio::test]
async fn an_operator_can_revoke_a_hosts_certs_and_re_enroll_it() {
    let s = start().await;
    signup_and_login(&s).await;
    let (host_id, agent) = enrolled_agent(&s, "compromised").await;

    // Give the host something worth keeping, so "revoke" is visibly not "delete".
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/env", s.base_url, host_id))
        .json(&serde_json::json!({"value": "prod"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts/{}/revoke-certs", s.base_url, host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "revoke: {:?}", r.text().await);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["revoked_certs"], 1);
    let new_token = body["bootstrap_token"].as_str().unwrap().to_string();

    assert_eq!(live_cert_count(&s, &host_id).await, 0);

    // The stolen key is dead on every agent route, renew included — otherwise revocation
    // would just be an invitation to mint a fresh cert.
    let mut agent = agent;
    assert!(agent.heartbeat().await.is_err());
    assert!(agent.fetch_desired_state(None).await.is_err());
    assert!(
        agent.renew().await.is_err(),
        "a revoked cert must not renew itself back into a valid one"
    );

    // The host row and its tag survived: this is a re-enrollment, not a rebuild.
    let detail: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts/{}", s.base_url, host_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        detail["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["key"] == "env" && t["value"] == "prod"),
        "revoking must not discard the host's configuration: {detail}"
    );

    // And the new token brings the same host back.
    let mut fresh = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(a) =
            fleet_agent_sim::enroll(&s.base_url, &new_token, Some("compromised"), None).await
        {
            fresh = Some(a);
            break;
        }
    }
    let fresh = fresh.expect("re-enrollment with the new bootstrap token failed");
    let mut alive = false;
    for _ in 0..8 {
        if fresh.heartbeat().await.is_ok() {
            alive = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(alive, "the re-enrolled host must be able to heartbeat");
    assert_eq!(live_cert_count(&s, &host_id).await, 1);
}

#[tokio::test]
async fn deleted_host_is_cut_off_and_gone() {
    let s = start().await;
    signup_and_login(&s).await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let create: serde_json::Value = r.json().await.unwrap();
    let host_id = create["host_id"].as_str().unwrap().to_string();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    // Enroll (retry for trust-store rebuild lag) and prove the agent is live.
    let mut agent = None;
    for _ in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        if let Ok(a) = fleet_agent_sim::enroll(&s.base_url, &token, Some("doomed"), None).await {
            agent = Some(a);
            break;
        }
    }
    let agent = agent.expect("enroll failed");
    let mut alive = false;
    for _ in 0..8 {
        if agent.heartbeat().await.is_ok() {
            alive = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(alive, "agent must be able to heartbeat before deletion");

    // Give the host a tag and an override so the cascade has something to clean up.
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/env", s.base_url, host_id))
        .json(&serde_json::json!({ "value": "prod" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    let r = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
        .json(&serde_json::json!({ "patch": { "secret": "x" } }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // Delete.
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{}", s.base_url, host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204, "delete failed");

    // Gone from the list, 404 on detail and on a second delete.
    let hosts: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(hosts.as_array().unwrap().is_empty());
    let r = s
        .cookie_jar
        .delete(format!("{}/api/hosts/{}", s.base_url, host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    // The live agent is cut off on EVERY agent route, not just heartbeat: revocation is
    // enforced once in the shared mTLS layer, so the cert serial no longer resolving as
    // active refuses desired-state and renew the same way. Renew in particular must be
    // refused — it is the endpoint that would otherwise mint a fresh, non-revoked cert.
    assert!(
        agent.heartbeat().await.is_err(),
        "deleted host's heartbeat must be rejected"
    );
    assert!(
        agent.fetch_desired_state(None).await.is_err(),
        "deleted host must not fetch desired state"
    );
    let mut agent = agent;
    assert!(
        agent.renew().await.is_err(),
        "deleted host must not renew itself back into a valid cert"
    );

    // No orphans left behind.
    for table in [
        "host_tags",
        "host_overrides",
        "host_facts",
        "host_fact_changes",
        "host_certs",
    ] {
        let n: i64 = sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {table} WHERE host_id = ?"))
            .bind(&host_id)
            .fetch_one(&s.db.read)
            .await
            .unwrap();
        assert_eq!(n, 0, "{table} rows must be deleted");
    }

    // Audit trail records the deletion.
    let n: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'host.deleted' AND target_id = ?",
    )
    .bind(&host_id)
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(n, 1);
}

/// Regression: a freshly created tenant's CA is not in the mTLS trust store until a rebuild
/// runs, and enrollment used to trigger that rebuild with a spawned, unawaited task. The
/// enroll response could therefore reach the agent first, and its opening mTLS connection
/// died with `UnknownCA` — while the server logged "not signed by any known tenant CA —
/// re-enroll the host", which is the wrong advice for a perfectly good enrollment.
///
/// Deterministic on purpose: rather than racing the scheduler, it asserts the gap exists
/// right after signup and that `ensure_tenant_trusted` closes it before returning.
#[tokio::test]
async fn a_new_tenants_ca_is_trusted_before_enrollment_answers() {
    let s = start().await;
    signup_and_login(&s).await;

    let tenant = fleet_storage::TenantRepo::new(&s.db)
        .get_by_slug("acme")
        .await
        .unwrap()
        .expect("signup created the tenant");

    // The gap this guards. Signup writes the CA to the database but nothing has reloaded
    // the in-memory trust store yet, so an mTLS handshake right now would be rejected.
    assert!(
        !s.state.trust_store.trusts_tenant(tenant.id),
        "precondition: a newly created tenant's CA is not yet loaded"
    );

    s.state
        .trust_store
        .ensure_tenant_trusted(tenant.id)
        .await
        .expect("the CA exists in the database, so a rebuild must pick it up");

    assert!(
        s.state.trust_store.trusts_tenant(tenant.id),
        "after ensure_tenant_trusted the CA must be usable for client-cert verification"
    );

    // Idempotent, and cheap the second time — no rebuild, just the in-memory check.
    s.state
        .trust_store
        .ensure_tenant_trusted(tenant.id)
        .await
        .unwrap();
    assert!(s.state.trust_store.trusts_tenant(tenant.id));
}

/// The end-to-end shape of the same bug: enroll, then immediately use the certificate with
/// no intervening delay. With the awaited guarantee in `enroll` this cannot race.
#[tokio::test]
async fn a_freshly_enrolled_host_can_connect_immediately() {
    let s = start().await;
    signup_and_login(&s).await;

    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let create: serde_json::Value = r.json().await.unwrap();
    let token = create["bootstrap_token"].as_str().unwrap().to_string();

    let agent = fleet_agent_sim::enroll(&s.base_url, &token, Some("first-host"), Some("linux"))
        .await
        .expect("first enrollment for a brand-new tenant must succeed");

    // No sleep, no retry: the enroll response is only correct if the CA is already loaded.
    agent
        .heartbeat()
        .await
        .expect("the first mTLS call after enrollment must not race the trust store");
}

/// "Add host" writes a row before anyone runs the install command, so the operator views
/// have to distinguish three states — not two. The one that matters is `never_enrolled`:
/// the token has expired, `HostRepo::enroll` will refuse it forever, and the row is
/// only good for deleting.
#[tokio::test]
async fn host_status_separates_never_enrolled_from_awaiting() {
    let s = start().await;
    signup_and_login(&s).await;

    let create_host = |s: &TestServer| {
        let req = s
            .cookie_jar
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}));
        async move {
            let v: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
            (
                v["host_id"].as_str().unwrap().to_string(),
                v["bootstrap_token"].as_str().unwrap().to_string(),
            )
        }
    };

    let status_of = |s: &TestServer, host_id: String| {
        let req = s.cookie_jar.get(format!("{}/api/hosts", s.base_url));
        async move {
            let hosts: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
            hosts
                .as_array()
                .unwrap()
                .iter()
                .find(|h| h["id"].as_str() == Some(&host_id))
                .unwrap_or_else(|| panic!("host {host_id} missing from list"))["status"]
                .as_str()
                .unwrap()
                .to_string()
        }
    };

    // Freshly added, install command not run: still actionable.
    let (waiting_id, _) = create_host(&s).await;
    assert_eq!(
        status_of(&s, waiting_id.clone()).await,
        "awaiting_enrollment"
    );

    // A host that ran the command has enrolled, and the status moves on to describing what
    // it is doing: it is in contact but has not reported applying anything yet (retried
    // while the trust store catches up, as elsewhere in this file).
    let (enrolled_id, token) = create_host(&s).await;
    let mut enrolled = false;
    for _ in 0..20 {
        if fleet_agent_sim::enroll(&s.base_url, &token, Some("beta"), Some("linux"))
            .await
            .is_ok()
        {
            enrolled = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(enrolled, "enroll failed after retries");
    assert_eq!(status_of(&s, enrolled_id).await, "out_of_sync");

    // Let the first host's token lapse. Nothing else about the row changes.
    sqlx::query("UPDATE hosts SET bootstrap_expires_at = ? WHERE id = ?")
        .bind(fleet_core::time::now_unix() - 1)
        .bind(&waiting_id)
        .execute(&s.db.write)
        .await
        .unwrap();

    assert_eq!(status_of(&s, waiting_id.clone()).await, "never_enrolled");

    // The detail endpoint must agree — it is the same derivation, and an operator who opens
    // the host from a "never enrolled" row must not see a different story.
    let detail: serde_json::Value = s
        .cookie_jar
        .get(format!("{}/api/hosts/{}", s.base_url, waiting_id))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(detail["status"], serde_json::json!("never_enrolled"));
}
