//! User management and the permission matrix it hands out.
//!
//! The point of these tests is that the roles are enforced by the *server*. The UI hides
//! controls a role cannot use, but that is a courtesy — every check below is made against
//! the HTTP API with a real session cookie for a real user.

mod common;

use common::{complete_exchange, signed_in, start_http};
use fleet_server::auth::tokens::hash_token;

use fleet_core::user::Role;
use fleet_storage::{MagicLinkRepo, TenantRepo, UserRepo};

async fn status(r: reqwest::Response) -> u16 {
    r.status().as_u16()
}

#[tokio::test]
async fn the_permission_matrix_is_enforced_by_the_server() {
    let s = start_http().await;
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

    // A host override reads back only for those who may write one: it is where per-host
    // credentials live, and reading it is not "reading the fleet".
    let code = status(
        owner
            .put(format!("{}/api/hosts/{}/override", s.base_url, host_id))
            .json(&serde_json::json!({ "patch": { "settings": { "x": { "secret": "s3" } } } }))
            .send()
            .await
            .unwrap(),
    )
    .await;
    assert_eq!(code, 204);
    for (name, c, want) in [
        ("owner", &owner, 200),
        ("admin", &admin, 200),
        ("add_hosts", &adder, 403),
        ("view_only", &viewer, 403),
    ] {
        let code = status(
            c.get(format!("{}/api/hosts/{}/override", s.base_url, host_id))
                .send()
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(code, want, "{name} reading a host override");
        let code = status(
            c.get(format!(
                "{}/api/hosts/{}/override/shape",
                s.base_url, host_id
            ))
            .send()
            .await
            .unwrap(),
        )
        .await;
        assert_eq!(code, want, "{name} reading a host override's shape");
    }

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
    let s = start_http().await;
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
    let r = complete_exchange(&invitee, &s.base_url, token).await;
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
    let s = start_http().await;
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
    let s = start_http().await;
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
    let s = start_http().await;
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
    let s = start_http().await;
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
