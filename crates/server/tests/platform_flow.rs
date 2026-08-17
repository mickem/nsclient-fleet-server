//! The platform console: cross-tenant administration.
//!
//! Two things are worth proving here and cannot be proved by reading the code. First, that
//! the gate holds — an owner, the most privileged role there is, gets nothing from these
//! routes without the platform-admin flag, and a platform admin reaches *other* tenants
//! rather than only their own. Second, that the edits actually land where they are enforced:
//! a cleared trial unblocks the tenant's next request, and a block cuts off the cookie and
//! the API key together.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_core::time::now_unix;
use fleet_core::user::Role;
use fleet_storage::{ApiKeyRepo, Db, SessionRepo, TenantRepo, UserRepo};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    _tempdir: TempDir,
    handle: tokio::task::JoinHandle<()>,
    db: Db,
    tenant_id: i64,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn start() -> TestServer {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");

    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let cfg = test_config(db_path);
    let (mtls_cert_pem, mtls_key_pem) =
        fleet_server::mtls::generate_self_signed_server("127.0.0.1").unwrap();
    let email = fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap();
    let turnstile =
        fleet_server::auth::turnstile::Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget);
    let trust_store =
        fleet_server::mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem)
            .await
            .unwrap();

    let state = fleet_server::AppState {
        db: db.clone(),
        config: cfg,
        email,
        turnstile,
        rate_limits,
        agent_limits: fleet_server::agent_limits::AgentRateLimits::new(),
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::default(),
        trust_store,
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store: Arc::new(fleet_server::bundles::LocalBundleStore::new(
            dir.path().join("bundles"),
        )),
        desired_state_cache: Default::default(),
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    let app = fleet_server::router(state);
    let handle = tokio::spawn(async move {
        let _ = axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await;
    });

    for _ in 0..50 {
        if reqwest::get(format!("{base_url}/healthz")).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    let tenant = TenantRepo::new(&db)
        .create("acme", "Acme", "free", None)
        .await
        .unwrap();

    TestServer {
        base_url,
        _tempdir: dir,
        handle,
        db,
        tenant_id: tenant.id,
    }
}

fn test_config(db_path: PathBuf) -> fleet_server::config::Config {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let key_b64 = MasterKey::generate_b64();
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();
    fleet_server::config::Config {
        listen: "127.0.0.1:0".into(),
        listen_https: "127.0.0.1:0".into(),
        listen_mtls: "127.0.0.1:0".into(),
        agent_mtls_url: "https://127.0.0.1".into(),
        acme: None,
        database_path: db_path,
        base_url: "http://localhost".into(),
        on_prem: false,
        on_prem_admin_email: None,
        on_prem_admin_password: None,
        platform_admin_emails: Vec::new(),
        magic_link_ttl_secs: 900,
        session_ttl_secs: 3600,
        bootstrap_ttl_secs: 3600,
        client_cert_lifetime_days: 90,
        cookie_secure: false,
        daily_email_budget: 1_000_000,
        smtp: None,
        turnstile_secret: None,
        master_key,
        bootstrap_jwt_secret,
    }
}

fn hash_token(token: &str) -> String {
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

fn client_with_session(base_url: &str, token: &str) -> reqwest::Client {
    let jar = reqwest::cookie::Jar::default();
    jar.add_cookie_str(
        &format!("fleet_session={token}; Path=/"),
        &base_url.parse().unwrap(),
    );
    reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// A user in the given tenant, plus a client already holding their session cookie.
async fn signed_in_for(
    s: &TestServer,
    tenant_id: i64,
    email: &str,
    role: Role,
) -> (i64, reqwest::Client) {
    let user = UserRepo::new(&s.db)
        .create(tenant_id, email, role)
        .await
        .unwrap();
    let token = format!("session-for-{email}");
    SessionRepo::new(&s.db)
        .create(&hash_token(&token), tenant_id, user.id, 3600)
        .await
        .unwrap();
    (user.id, client_with_session(&s.base_url, &token))
}

async fn signed_in(s: &TestServer, email: &str, role: Role) -> (i64, reqwest::Client) {
    signed_in_for(s, s.tenant_id, email, role).await
}

/// A signed-in user who also holds the platform-admin flag. Their own role stays ordinary —
/// the point being that the flag, not the role, is what opens the console.
async fn platform_admin(s: &TestServer, email: &str) -> (i64, reqwest::Client) {
    let (id, c) = signed_in(s, email, Role::ViewOnly).await;
    UserRepo::new(&s.db)
        .set_platform_admin(id, true)
        .await
        .unwrap();
    (id, c)
}

#[tokio::test]
async fn the_flag_is_what_opens_the_console_not_the_role() {
    let s = start().await;
    let (_, owner) = signed_in(&s, "owner@example.com", Role::Owner).await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;
    let anon = reqwest::Client::new();

    let routes = [
        "/api/platform/tenants",
        "/api/platform/tiers",
        "/api/platform/settings",
    ];

    for path in routes {
        // An owner has every permission their tenant can grant, and none of them is this one.
        let r = owner
            .get(format!("{}{}", s.base_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 403, "an owner must not reach {path}");

        let r = anon
            .get(format!("{}{}", s.base_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "an anonymous caller must not reach {path}");

        let r = admin
            .get(format!("{}{}", s.base_url, path))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 200, "the platform admin must reach {path}");
    }

    // The writes are gated by the same extractor, so one is enough to show the pattern holds
    // for them too.
    let r = owner
        .post(format!("{}/api/platform/tenants", s.base_url))
        .json(&serde_json::json!({ "slug": "sneaky", "name": "Sneaky", "tier": "free" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);
}

#[tokio::test]
async fn the_console_sees_and_edits_other_tenants() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;

    // A second tenant the admin has no membership of at all.
    let other = TenantRepo::new(&s.db)
        .create("other", "Other Corp", "free", Some(now_unix() + 3600))
        .await
        .unwrap();
    signed_in_for(&s, other.id, "victim@other.example", Role::Owner).await;

    let tenants: serde_json::Value = admin
        .get(format!("{}/api/platform/tenants", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let rows = tenants.as_array().unwrap();
    assert_eq!(rows.len(), 2, "every tenant on the estate is listed");
    let row = rows
        .iter()
        .find(|t| t["slug"] == serde_json::json!("other"))
        .expect("the other tenant must be visible");
    assert_eq!(row["tier"], serde_json::json!("free"));
    assert_eq!(row["effective"]["max_hosts"], serde_json::json!(5));
    assert_eq!(row["user_count"], serde_json::json!(1));

    // Its users are readable from outside it.
    let users: serde_json::Value = admin
        .get(format!(
            "{}/api/platform/tenants/{}/users",
            s.base_url, other.id
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(users.as_array().unwrap().len(), 1);
    assert_eq!(users[0]["email"], serde_json::json!("victim@other.example"));
    assert_eq!(users[0]["role"], serde_json::json!("owner"));

    // Subscription: a named tier plus one override on top of it.
    let r = admin
        .put(format!(
            "{}/api/platform/tenants/{}/subscription",
            s.base_url, other.id
        ))
        .json(&serde_json::json!({
            "tier": "pro",
            "trial_expires_at": null,
            "overrides": { "max_hosts": 1234 },
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let updated: serde_json::Value = r.json().await.unwrap();
    assert_eq!(updated["tier"], serde_json::json!("pro"));
    assert_eq!(
        updated["effective"]["max_hosts"],
        serde_json::json!(1234),
        "the override wins over the named tier"
    );
    assert_eq!(
        updated["effective"]["max_bundle_mb"],
        serde_json::json!(100),
        "fields with no override keep the tier's value"
    );
    assert_eq!(updated["trial_expires_at"], serde_json::Value::Null);

    // An unknown tier is refused rather than silently treated as free.
    let r = admin
        .put(format!(
            "{}/api/platform/tenants/{}/subscription",
            s.base_url, other.id
        ))
        .json(&serde_json::json!({ "tier": "platinum" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // Clearing every override puts the tenant back on the plain tier, with nothing stored.
    let r = admin
        .put(format!(
            "{}/api/platform/tenants/{}/subscription",
            s.base_url, other.id
        ))
        .json(&serde_json::json!({ "tier": "pro", "overrides": null }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let stored: Option<String> =
        sqlx::query_scalar("SELECT tier_overrides_json FROM tenants WHERE id = ?")
            .bind(other.id)
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(stored, None);

    // The tenant's own audit log records what was done to it, and by whom.
    let entry: (String, Option<String>) = sqlx::query_as(
        "SELECT action, metadata_json FROM audit_log
          WHERE tenant_id = ? AND action = 'tenant.subscription_changed'
          ORDER BY ts DESC LIMIT 1",
    )
    .bind(other.id)
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert!(entry.1.unwrap().contains("ops@vendor.example"));
}

/// Fleet-wide drift, per tenant: how many of a tenant's hosts have configuration of their
/// own that outranks what we send them.
///
/// Only hosts that have actually said so are counted. A host whose agent predates the flag
/// reports nothing, and counting that as drift would inflate the number with hosts nobody
/// has any evidence about — the same reason the column is nullable in the first place.
#[tokio::test]
async fn the_console_counts_hosts_that_are_only_partly_fleet_managed() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;

    // Three enrolled hosts, one per answer the agent can give.
    for (id, local) in [
        ("host-drifted", Some(1_i64)),
        ("host-clean", Some(0)),
        ("host-silent", None),
    ] {
        sqlx::query(
            "INSERT INTO hosts (id, tenant_id, enrolled_at, created_at, local_config_present)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(s.tenant_id)
        .bind(now_unix())
        .bind(now_unix())
        .bind(local)
        .execute(&s.db.write)
        .await
        .unwrap();
    }

    let row = |tenants: serde_json::Value| {
        tenants
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["slug"] == serde_json::json!("acme"))
            .cloned()
            .expect("the tenant must be listed")
    };
    let listed: serde_json::Value = admin
        .get(format!("{}/api/platform/tenants", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let t = row(listed);
    assert_eq!(t["host_count"], serde_json::json!(3));
    assert_eq!(
        t["local_config_host_count"],
        serde_json::json!(1),
        "only the host that reported local configuration counts"
    );

    // The subscription response is counted the same way, rather than reporting zeros for
    // everything the edit did not touch.
    let updated: serde_json::Value = admin
        .put(format!(
            "{}/api/platform/tenants/{}/subscription",
            s.base_url, s.tenant_id
        ))
        .json(&serde_json::json!({ "tier": "pro" }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated["host_count"], serde_json::json!(3));
    assert_eq!(updated["local_config_host_count"], serde_json::json!(1));
}

#[tokio::test]
async fn extending_a_trial_unblocks_the_tenant_immediately() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;

    let expired = TenantRepo::new(&s.db)
        .create("lapsed", "Lapsed", "free", Some(now_unix() - 60))
        .await
        .unwrap();
    let (_, customer) = signed_in_for(&s, expired.id, "cust@lapsed.example", Role::Owner).await;

    // The trial-expiry layer is refusing everything the customer does.
    let r = customer
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 402);

    let r = admin
        .put(format!(
            "{}/api/platform/tenants/{}/subscription",
            s.base_url, expired.id
        ))
        .json(&serde_json::json!({
            "tier": "starter",
            "trial_expires_at": null,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // Same cookie, no re-login: the limit is read from the tenant row where it is enforced.
    let r = customer
        .get(format!("{}/api/hosts", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        200,
        "clearing the trial must take effect on the next request"
    );
}

#[tokio::test]
async fn blocking_cuts_off_the_cookie_and_the_api_key_together() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;
    let (victim_id, victim) = signed_in(&s, "victim@example.com", Role::Admin).await;

    // The victim also has automation running under an API key, which is the half of their
    // access that a naive block would leave standing.
    let key_token = "nsk_platform_flow_key";
    ApiKeyRepo::new(&s.db)
        .create(
            s.tenant_id,
            victim_id,
            "ci",
            &hash_token(key_token),
            "nsk_platf",
        )
        .await
        .unwrap();
    let with_key = reqwest::Client::new();
    let key_call = || {
        with_key
            .get(format!("{}/api/hosts", s.base_url))
            .bearer_auth(key_token)
            .send()
    };

    assert_eq!(
        victim
            .get(format!("{}/api/hosts", s.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(key_call().await.unwrap().status(), 200);

    let r = admin
        .patch(format!("{}/api/platform/users/{}", s.base_url, victim_id))
        .json(&serde_json::json!({ "blocked": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    assert_eq!(
        victim
            .get(format!("{}/api/hosts", s.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        401,
        "the session cookie must stop working"
    );
    assert_eq!(
        key_call().await.unwrap().status(),
        401,
        "the API key must stop working too"
    );

    // The account is still there, and so is their key — blocking is reversible, which is the
    // whole reason it exists next to deletion.
    let keys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE user_id = ?")
        .bind(victim_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(keys, 1);

    // A blocked user cannot get back in through the front door either: no link is issued.
    let r = reqwest::Client::new()
        .post(format!("{}/api/auth/send-link", s.base_url))
        .json(&serde_json::json!({ "email": "victim@example.com" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204, "the response stays uniform");
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links WHERE user_id = ?")
        .bind(victim_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(links, 0);

    let r = admin
        .patch(format!("{}/api/platform/users/{}", s.base_url, victim_id))
        .json(&serde_json::json!({ "blocked": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        key_call().await.unwrap().status(),
        200,
        "unblocking restores the key without reissuing it"
    );
}

#[tokio::test]
async fn the_console_cannot_lock_itself_or_a_tenant_out() {
    let s = start().await;
    let (admin_id, admin) = platform_admin(&s, "ops@vendor.example").await;

    // Not yourself, by either route — the rule that guarantees somebody still holds the
    // console when the request finishes.
    for body in [
        serde_json::json!({ "blocked": true }),
        serde_json::json!({ "platform_admin": false }),
    ] {
        let r = admin
            .patch(format!("{}/api/platform/users/{}", s.base_url, admin_id))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "self-directed change must be refused");
    }
    let r = admin
        .delete(format!("{}/api/platform/users/{}", s.base_url, admin_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 400);

    // A tenant's only owner cannot be deleted — that would leave the tenant with nobody who
    // can manage it, and there is no way back from there.
    let (owner_id, _) = signed_in(&s, "owner@example.com", Role::Owner).await;
    let r = admin
        .delete(format!("{}/api/platform/users/{}", s.base_url, owner_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);

    // Blocking that same owner is allowed: it stops them without stranding the tenant.
    let r = admin
        .patch(format!("{}/api/platform/users/{}", s.base_url, owner_id))
        .json(&serde_json::json!({ "blocked": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // With a second owner in place the first can go.
    let (second_owner_id, _) = signed_in(&s, "owner2@example.com", Role::Owner).await;
    let r = admin
        .delete(format!("{}/api/platform/users/{}", s.base_url, owner_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert!(UserRepo::new(&s.db)
        .get_any(second_owner_id)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn granting_the_flag_hands_over_the_console() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;
    let (colleague_id, colleague) = signed_in(&s, "colleague@vendor.example", Role::ViewOnly).await;

    assert_eq!(
        colleague
            .get(format!("{}/api/platform/tenants", s.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );

    let r = admin
        .patch(format!(
            "{}/api/platform/users/{}",
            s.base_url, colleague_id
        ))
        .json(&serde_json::json!({ "platform_admin": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    // No re-login: the flag is re-read on every request, exactly like the role.
    assert_eq!(
        colleague
            .get(format!("{}/api/platform/tenants", s.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let me: serde_json::Value = colleague
        .get(format!("{}/api/me", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(me["is_platform_admin"], serde_json::json!(true));
    assert_eq!(
        me["role"],
        serde_json::json!("view_only"),
        "the flag grants nothing inside their own tenant"
    );

    // And a peer can take it away again.
    let r = admin
        .patch(format!(
            "{}/api/platform/users/{}",
            s.base_url, colleague_id
        ))
        .json(&serde_json::json!({ "platform_admin": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        colleague
            .get(format!("{}/api/platform/tenants", s.base_url))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
}

#[tokio::test]
async fn creating_a_tenant_provisions_its_ca_and_its_owner() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;

    let r = admin
        .post(format!("{}/api/platform/tenants", s.base_url))
        .json(&serde_json::json!({
            "slug": "Newco",                      // uppercase is normalised, not refused
            "name": "  Newco Ltd  ",
            "tier": "starter",
            "trial_days": 30,
            "owner_email": "boss@newco.example",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let created: serde_json::Value = r.json().await.unwrap();
    assert_eq!(created["tenant"]["slug"], serde_json::json!("newco"));
    assert_eq!(created["tenant"]["name"], serde_json::json!("Newco Ltd"));
    assert_eq!(
        created["tenant"]["effective"]["max_hosts"],
        serde_json::json!(50)
    );
    assert_eq!(created["owner_invited"], serde_json::json!(true));
    let trial = created["tenant"]["trial_expires_at"].as_i64().unwrap();
    assert!(trial > now_unix() + 29 * 86_400 && trial <= now_unix() + 30 * 86_400);

    let tenant_id = created["tenant"]["id"].as_i64().unwrap();

    // A tenant without a CA cannot enrol anything, so provisioning one is part of creating it.
    let secrets: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM tenant_secrets WHERE tenant_id = ?")
            .bind(tenant_id)
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_eq!(secrets, 1);

    // The owner exists and has been sent the one link that lets them in.
    let owner = UserRepo::new(&s.db)
        .find_by_email("boss@newco.example")
        .await
        .unwrap()
        .expect("owner must exist");
    assert_eq!(owner.tenant_id, tenant_id);
    assert_eq!(owner.role, Role::Owner);
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links WHERE user_id = ?")
        .bind(owner.id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(links, 1);

    // Slugs that would end up in a certificate DN are refused outright.
    for bad in ["has space", "trailing-", "dots.here", ""] {
        let r = admin
            .post(format!("{}/api/platform/tenants", s.base_url))
            .json(&serde_json::json!({ "slug": bad, "name": "X", "tier": "free" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "slug {bad:?} must be refused");
    }

    // Taken slug, and an address that already belongs to another tenant.
    let r = admin
        .post(format!("{}/api/platform/tenants", s.base_url))
        .json(&serde_json::json!({ "slug": "newco", "name": "Dup", "tier": "free" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    let r = admin
        .post(format!("{}/api/platform/tenants", s.base_url))
        .json(&serde_json::json!({
            "slug": "newco2", "name": "Dup", "tier": "free",
            "owner_email": "boss@newco.example",
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
}

#[tokio::test]
async fn the_signup_switch_closes_the_front_door() {
    let s = start().await;
    let (_, admin) = platform_admin(&s, "ops@vendor.example").await;
    let anon = reqwest::Client::new();

    let signup = |slug: &str, email: &str| {
        let url = format!("{}/api/auth/signup", s.base_url);
        let body = serde_json::json!({
            "email": email, "tenant_slug": slug, "tenant_name": "X", "turnstile_token": "",
        });
        let c = reqwest::Client::new();
        async move { c.post(url).json(&body).send().await.unwrap().status() }
    };

    // Open by default: no row in platform_settings, and signup works.
    let cfg: serde_json::Value = anon
        .get(format!("{}/api/public-config", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["signups_enabled"], serde_json::json!(true));
    assert_eq!(signup("first", "one@example.com").await, 204);

    let r = admin
        .put(format!("{}/api/platform/settings", s.base_url))
        .json(&serde_json::json!({ "signups_enabled": false }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    assert_eq!(
        signup("second", "two@example.com").await,
        403,
        "signup must be refused while the switch is off"
    );
    let tenants: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE slug = 'second'")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(tenants, 0, "nothing may be created by a refused signup");

    // The sign-in page is told, so it can stop offering a form that cannot succeed.
    let cfg: serde_json::Value = anon
        .get(format!("{}/api/public-config", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(cfg["signups_enabled"], serde_json::json!(false));

    // Invitations are unaffected — closing self-service is not closing the product.
    let (_, tenant_admin) = signed_in(&s, "admin@acme.example", Role::Admin).await;
    let r = tenant_admin
        .post(format!("{}/api/users", s.base_url))
        .json(&serde_json::json!({ "email": "colleague@acme.example", "role": "view_only" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let r = admin
        .put(format!("{}/api/platform/settings", s.base_url))
        .json(&serde_json::json!({ "signups_enabled": true }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(signup("third", "three@example.com").await, 204);
}
