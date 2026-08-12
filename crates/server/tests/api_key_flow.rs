//! API keys: bearer authentication, and the fact that a key is never more privileged than
//! the user it belongs to.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_core::user::Role;
use fleet_storage::{Db, SessionRepo, TenantRepo, UserRepo};
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

/// A user of the given role, plus a client already holding their session cookie.
///
/// The session is minted directly rather than through the magic-link flow: this file is
/// about what a role may do once signed in, and `auth_flow` already covers getting there.
async fn signed_in(s: &TestServer, email: &str, role: Role) -> (i64, reqwest::Client) {
    let user = UserRepo::new(&s.db)
        .create(s.tenant_id, email, role)
        .await
        .unwrap();

    let token = format!("session-for-{email}");
    SessionRepo::new(&s.db)
        .create(&hash_token(&token), s.tenant_id, user.id, 3600)
        .await
        .unwrap();

    let jar = reqwest::cookie::Jar::default();
    jar.add_cookie_str(
        &format!("fleet_session={token}; Path=/"),
        &s.base_url.parse().unwrap(),
    );
    let client = reqwest::Client::builder()
        .cookie_provider(Arc::new(jar))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    (user.id, client)
}

/// Issue a key for `client`'s user and return the plaintext token, exactly as an operator
/// would get it from the UI.
async fn mint_key(s: &TestServer, client: &reqwest::Client, name: &str) -> String {
    let r = client
        .post(format!("{}/api/keys", s.base_url))
        .json(&serde_json::json!({ "name": name }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "key creation");
    let body: serde_json::Value = r.json().await.unwrap();
    body["token"].as_str().unwrap().to_string()
}

/// A client with no cookie jar — the state a `curl` invocation is in.
fn bare() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn get_hosts_with(s: &TestServer, authorization: &str) -> u16 {
    bare()
        .get(format!("{}/api/hosts", s.base_url))
        .header("Authorization", authorization)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn post_hosts_with(s: &TestServer, token: &str) -> u16 {
    bare()
        .post(format!("{}/api/hosts", s.base_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_key_provisions_an_installer_token_over_curl() {
    let s = start().await;
    let (_, adder) = signed_in(&s, "ci@example.com", Role::AddHosts).await;
    let token = mint_key(&s, &adder, "ci-provisioning").await;

    // No cookie, no body, no content-type — the shape of the documented one-liner.
    let r = bare()
        .post(format!("{}/api/hosts", s.base_url))
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "bearer auth must provision a host");

    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body["install_command"]
            .as_str()
            .unwrap()
            .contains(body["bootstrap_token"].as_str().unwrap()),
        "the response must carry a runnable install command"
    );

    // The scheme is matched case-insensitively, per RFC 7235.
    let lower = format!("bearer {token}");
    assert_eq!(get_hosts_with(&s, &lower).await, 200);
}

#[tokio::test]
async fn a_key_is_never_more_privileged_than_its_owner() {
    let s = start().await;
    let (viewer_id, viewer) = signed_in(&s, "viewer@example.com", Role::ViewOnly).await;
    let (_, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;
    let token = mint_key(&s, &viewer, "read-only").await;

    // Reading is fine; provisioning is not — the same rules as the owner's browser session.
    assert_eq!(get_hosts_with(&s, &format!("Bearer {token}")).await, 200);
    assert_eq!(post_hosts_with(&s, &token).await, 403);

    // Promote the owner: the key follows, without being reissued.
    let r = admin
        .patch(format!("{}/api/users/{}", s.base_url, viewer_id))
        .json(&serde_json::json!({ "role": "add_hosts" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        post_hosts_with(&s, &token).await,
        200,
        "a promotion must reach existing keys"
    );

    // And demotion revokes the capability just as immediately.
    let r = admin
        .patch(format!("{}/api/users/{}", s.base_url, viewer_id))
        .json(&serde_json::json!({ "role": "view_only" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(post_hosts_with(&s, &token).await, 403);
}

#[tokio::test]
async fn tokens_are_stored_hashed_and_shown_once() {
    let s = start().await;
    let (user_id, client) = signed_in(&s, "dev@example.com", Role::Admin).await;
    let token = mint_key(&s, &client, "laptop").await;

    assert!(
        token.starts_with("nsk_"),
        "tokens are identifiable: {token}"
    );

    // Nothing resembling the plaintext is in the row…
    let stored: (String, String) =
        sqlx::query_as("SELECT token_hash, token_prefix FROM api_keys WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&s.db.read)
            .await
            .unwrap();
    assert_ne!(stored.0, token);
    assert!(!stored.0.contains(&token[4..]));
    assert!(token.starts_with(&stored.1), "prefix must match the token");
    assert_eq!(stored.1.len(), 12, "prefix stays short: nsk_ plus 8");

    // …and the listing never hands it back.
    let listed: serde_json::Value = client
        .get(format!("{}/api/keys", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let row = &listed.as_array().unwrap()[0];
    assert!(
        row.get("token").is_none(),
        "list must not expose the secret"
    );
    assert_eq!(row["token_prefix"], serde_json::json!(stored.1));
}

#[tokio::test]
async fn revoking_and_deleting_kill_the_key() {
    let s = start().await;
    let (_, owner) = signed_in(&s, "owner@example.com", Role::Admin).await;
    let (victim_id, victim) = signed_in(&s, "victim@example.com", Role::AddHosts).await;

    let revoked = mint_key(&s, &owner, "to-revoke").await;
    let orphaned = mint_key(&s, &victim, "belongs-to-victim").await;
    assert_eq!(get_hosts_with(&s, &format!("Bearer {revoked}")).await, 200);

    // Explicit revocation.
    let listed: serde_json::Value = owner
        .get(format!("{}/api/keys", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = listed.as_array().unwrap()[0]["id"].as_str().unwrap();
    let r = owner
        .delete(format!("{}/api/keys/{}", s.base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        get_hosts_with(&s, &format!("Bearer {revoked}")).await,
        401,
        "a revoked key must stop working"
    );

    // Deleting a user takes their keys with them — otherwise a departing colleague's
    // automation would outlive their account.
    assert_eq!(get_hosts_with(&s, &format!("Bearer {orphaned}")).await, 200);
    let r = owner
        .delete(format!("{}/api/users/{}", s.base_url, victim_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        get_hosts_with(&s, &format!("Bearer {orphaned}")).await,
        401,
        "deleting a user must revoke their keys"
    );

    let left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM api_keys WHERE user_id = ?")
        .bind(victim_id)
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(left, 0);
}

#[tokio::test]
async fn keys_are_private_to_their_owner() {
    let s = start().await;
    let (_, alice) = signed_in(&s, "alice@example.com", Role::Admin).await;
    let (_, bob) = signed_in(&s, "bob@example.com", Role::Admin).await;

    mint_key(&s, &alice, "alice-key").await;
    let listed: serde_json::Value = bob
        .get(format!("{}/api/keys", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        listed.as_array().unwrap().is_empty(),
        "an admin must not see another user's keys"
    );

    // Nor revoke one: scoped to the caller, so it reads as absent rather than forbidden.
    let alice_keys: serde_json::Value = alice
        .get(format!("{}/api/keys", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = alice_keys.as_array().unwrap()[0]["id"].as_str().unwrap();
    let r = bob
        .delete(format!("{}/api/keys/{}", s.base_url, id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

#[tokio::test]
async fn bad_bearer_tokens_authenticate_nothing() {
    let s = start().await;
    let (_, client) = signed_in(&s, "dev@example.com", Role::Admin).await;
    let token = mint_key(&s, &client, "real").await;

    for (label, header) in [
        ("garbage", "Bearer nsk_not-a-real-token".to_string()),
        ("empty", "Bearer ".to_string()),
        ("wrong scheme", format!("Basic {token}")),
        ("no scheme", token.clone()),
        (
            "truncated to its prefix",
            format!("Bearer {}", &token[..12]),
        ),
    ] {
        assert_eq!(
            get_hosts_with(&s, &header).await,
            401,
            "{label} must not authenticate"
        );
    }

    // last_used_at is recorded, so a key that is never used — or one being used when it
    // should not be — is visible in the listing.
    let before: Option<i64> = sqlx::query_scalar("SELECT last_used_at FROM api_keys")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(before, None, "a fresh key has never been used");
    assert_eq!(get_hosts_with(&s, &format!("Bearer {token}")).await, 200);
    let after: Option<i64> = sqlx::query_scalar("SELECT last_used_at FROM api_keys")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert!(after.is_some(), "use must be recorded");
}
