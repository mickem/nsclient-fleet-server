//! User management and the permission matrix it hands out.
//!
//! The point of these tests is that the roles are enforced by the *server*. The UI hides
//! controls a role cannot use, but that is a courtesy — every check below is made against
//! the HTTP API with a real session cookie for a real user.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_core::user::Role;
use fleet_storage::{Db, MagicLinkRepo, SessionRepo, TenantRepo, UserRepo};
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

async fn status(r: reqwest::Response) -> u16 {
    r.status().as_u16()
}

#[tokio::test]
async fn the_permission_matrix_is_enforced_by_the_server() {
    let s = start().await;
    let (_, owner) = signed_in(&s, "owner@example.com", Role::Owner).await;
    let (_, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;
    let (_, adder) = signed_in(&s, "adder@example.com", Role::AddHosts).await;
    let (_, viewer) = signed_in(&s, "viewer@example.com", Role::ViewOnly).await;

    // Everyone signed in can read the fleet.
    for (name, c) in [
        ("owner", &owner),
        ("admin", &admin),
        ("add_hosts", &adder),
        ("view_only", &viewer),
    ] {
        let code = status(
            c.get(format!("{}/api/hosts", s.base_url))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(code, 200, "{name} must be able to list hosts");
    }

    // Adding a host: everyone except view_only.
    for (name, c, want) in [
        ("owner", &owner, 200),
        ("admin", &admin, 200),
        ("add_hosts", &adder, 200),
        ("view_only", &viewer, 403),
    ] {
        let code = status(
            c.post(format!("{}/api/hosts", s.base_url))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(code, want, "{name} adding a host");
    }

    // Changing configuration: admins only. `add_hosts` gets exactly one write, and this
    // is not it.
    for (name, c, want) in [
        ("owner", &owner, 201),
        ("admin", &admin, 201),
        ("add_hosts", &adder, 403),
        ("view_only", &viewer, 403),
    ] {
        let code = status(
            c.post(format!("{}/api/groups", s.base_url))
                .json(&serde_json::json!({ "name": format!("g-{name}"), "selector": { "clauses": [] } }))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(code, want, "{name} creating a group");
    }

    // Deleting a host is a configuration change, not an "add hosts" one.
    let created: serde_json::Value = adder
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let host_id = created["host_id"].as_str().unwrap();
    let code = status(
        adder
            .delete(format!("{}/api/hosts/{}", s.base_url, host_id))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 403, "add_hosts must not delete the host it created");

    // User management: admins only, and the listing is not readable by anyone else.
    for (name, c, want) in [
        ("owner", &owner, 200),
        ("admin", &admin, 200),
        ("add_hosts", &adder, 403),
        ("view_only", &viewer, 403),
    ] {
        let code = status(
            c.get(format!("{}/api/users", s.base_url))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(code, want, "{name} listing users");
    }
}

#[tokio::test]
async fn invite_creates_a_user_with_the_requested_role() {
    let s = start().await;
    let (_, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;

    let r = admin
        .post(format!("{}/api/users", s.base_url))
        .json(&serde_json::json!({ "email": "New.Person@Example.com", "role": "add_hosts" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let created: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        created["email"],
        serde_json::json!("new.person@example.com")
    );
    assert_eq!(created["role"], serde_json::json!("add_hosts"));

    // A magic link was issued for them, which is the only way they can sign in.
    let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM magic_links WHERE user_id = ?")
        .bind(created["id"].as_i64().unwrap())
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(links, 1, "the invitation must issue exactly one link");

    // The role is live immediately: the invitee can add a host but not change config.
    let token = "invitee-link";
    MagicLinkRepo::new(&s.db)
        .create(
            &hash_token(token),
            s.tenant_id,
            created["id"].as_i64().unwrap(),
            fleet_core::time::now_unix() + 600,
        )
        .await
        .unwrap();
    let invitee = reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let r = invitee
        .get(format!("{}/api/auth/exchange?t={}", s.base_url, token))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 303, "the invited user must be able to sign in");

    let code = status(
        invitee
            .post(format!("{}/api/hosts", s.base_url))
            .json(&serde_json::json!({}))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 200);
    let code = status(
        invitee
            .post(format!("{}/api/groups", s.base_url))
            .json(&serde_json::json!({ "name": "g", "selector": { "clauses": [] } }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 403, "add_hosts must not create groups");
}

#[tokio::test]
async fn invite_rejects_owner_role_and_duplicate_addresses() {
    let s = start().await;
    let (_, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;

    // `owner` is not in the assignable set — it is established at signup.
    let code = status(
        admin
            .post(format!("{}/api/users", s.base_url))
            .json(&serde_json::json!({ "email": "x@example.com", "role": "owner" }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 400);

    // Sign-in resolves an address to exactly one account, so a duplicate is refused —
    // including one already used in another tenant.
    let other = TenantRepo::new(&s.db)
        .create("other", "Other", "free", None)
        .await
        .unwrap();
    UserRepo::new(&s.db)
        .create(other.id, "taken@example.com", Role::Admin)
        .await
        .unwrap();
    let code = status(
        admin
            .post(format!("{}/api/users", s.base_url))
            .json(&serde_json::json!({ "email": "taken@example.com", "role": "view_only" }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 409);
}

#[tokio::test]
async fn role_changes_take_effect_on_the_next_request() {
    let s = start().await;
    let (_, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;
    let (viewer_id, viewer) = signed_in(&s, "viewer@example.com", Role::ViewOnly).await;

    let add_host = |c: reqwest::Client| {
        let url = format!("{}/api/hosts", s.base_url);
        async move {
            status(
                c.post(url)
                    .json(&serde_json::json!({}))
                    .send()
                    .await
                    .unwrap(),
            )
            .await
        }
    };

    assert_eq!(add_host(viewer.clone()).await, 403);

    let r = admin
        .patch(format!("{}/api/users/{}", s.base_url, viewer_id))
        .json(&serde_json::json!({ "role": "add_hosts" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // Same cookie, no re-login: the session layer re-reads the role every request.
    assert_eq!(
        add_host(viewer.clone()).await,
        200,
        "a promotion must not require signing in again"
    );

    let r = admin
        .patch(format!("{}/api/users/{}", s.base_url, viewer_id))
        .json(&serde_json::json!({ "role": "view_only" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
    assert_eq!(
        add_host(viewer).await,
        403,
        "a demotion must take effect immediately"
    );
}

#[tokio::test]
async fn delete_removes_the_user_and_signs_them_out() {
    let s = start().await;
    let (_, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;
    let (victim_id, victim) = signed_in(&s, "victim@example.com", Role::AddHosts).await;

    // They authored something first, so we can prove the audit trail survives them.
    let r = victim
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let r = admin
        .delete(format!("{}/api/users/{}", s.base_url, victim_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);

    // The session is gone: the cookie no longer authenticates anything.
    let code = status(
        victim
            .get(format!("{}/api/hosts", s.base_url))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 401, "deleting a user must sign them out");

    // The record of what they did stays, with attribution dropped rather than the row.
    let orphaned: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'host.created' AND user_id IS NULL",
    )
    .fetch_one(&s.db.read)
    .await
    .unwrap();
    assert_eq!(orphaned, 1, "audit entries outlive the account");
}

#[tokio::test]
async fn a_tenant_cannot_lock_itself_out() {
    let s = start().await;
    let (owner_id, _owner) = signed_in(&s, "owner@example.com", Role::Owner).await;
    let (admin_id, admin) = signed_in(&s, "admin@example.com", Role::Admin).await;

    // Not yourself — the quickest way to strand a tenant by accident.
    assert_eq!(
        status(
            admin
                .delete(format!("{}/api/users/{}", s.base_url, admin_id))
                .send()
                .await
                .unwrap()
        )
        .await,
        400
    );
    assert_eq!(
        status(
            admin
                .patch(format!("{}/api/users/{}", s.base_url, admin_id))
                .json(&serde_json::json!({ "role": "view_only" }))
                .send()
                .await
                .unwrap()
        )
        .await,
        400
    );

    // Not the owner, by either route.
    assert_eq!(
        status(
            admin
                .delete(format!("{}/api/users/{}", s.base_url, owner_id))
                .send()
                .await
                .unwrap()
        )
        .await,
        403
    );
    assert_eq!(
        status(
            admin
                .patch(format!("{}/api/users/{}", s.base_url, owner_id))
                .json(&serde_json::json!({ "role": "view_only" }))
                .send()
                .await
                .unwrap()
        )
        .await,
        403
    );

    // No "last manager" counter is needed on top of these two: reaching this endpoint
    // requires managing users, and neither rule lets the caller act on their own row, so a
    // manager is always left standing. Demoting every *other* admin is allowed, and leaves
    // the caller in charge.
    let (other_admin_id, _) = signed_in(&s, "other@example.com", Role::Admin).await;
    assert_eq!(
        status(
            admin
                .patch(format!("{}/api/users/{}", s.base_url, other_admin_id))
                .json(&serde_json::json!({ "role": "view_only" }))
                .send()
                .await
                .unwrap()
        )
        .await,
        204
    );
    let me: serde_json::Value = admin
        .get(format!("{}/api/me", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        me["role"],
        serde_json::json!("admin"),
        "the caller still manages users"
    );
}
