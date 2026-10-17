//! API keys: bearer authentication, and the fact that a key is never more privileged than
//! the user it belongs to.

mod common;

use common::{signed_in, start_http, HttpServer};
use fleet_server::auth::tokens::hash_token;

use fleet_core::user::Role;
use fleet_storage::ApiKeyRepo;

/// Issue a key for `client`'s user and return the plaintext token, exactly as an operator
/// would get it from the UI.
async fn mint_key(s: &HttpServer, client: &reqwest::Client, name: &str) -> String {
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

async fn get_hosts_with(s: &HttpServer, authorization: &str) -> u16 {
    bare()
        .get(format!("{}/api/hosts", s.base_url))
        .header("Authorization", authorization)
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

async fn post_hosts_with(s: &HttpServer, token: &str) -> u16 {
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
    let s = start_http().await;
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
    let s = start_http().await;
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
    let s = start_http().await;
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
    let s = start_http().await;
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

/// Revoking a leaked key has to actually revoke it. If the key can mint another, whoever
/// holds it makes a replacement first and the replacement survives the revocation — so the
/// only remaining lever is deleting the owner.
#[tokio::test]
async fn a_key_cannot_mint_another_key() {
    let s = start_http().await;
    let (_, alice) = signed_in(&s, "alice@example.com", Role::Admin).await;
    let token = mint_key(&s, &alice, "ci").await;

    let r = bare()
        .post(format!("{}/api/keys", s.base_url))
        .bearer_auth(&token)
        .json(&serde_json::json!({ "name": "replacement" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 403);

    // ...and it really is the credential kind that is refused, not the role: the same user
    // through a cookie still can.
    let r = alice
        .post(format!("{}/api/keys", s.base_url))
        .json(&serde_json::json!({ "name": "second" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}

/// A key never expired, so a leaked one stayed a working credential until somebody noticed.
#[tokio::test]
async fn an_expired_key_authenticates_nothing() {
    let s = start_http().await;
    let (user_id, _alice) = signed_in(&s, "alice@example.com", Role::Admin).await;

    let live = "nsk_still_good";
    let dead = "nsk_ran_out";
    let keys = ApiKeyRepo::new(&s.db);
    keys.create(
        s.tenant_id,
        user_id,
        "live",
        &hash_token(live),
        "nsk_live",
        Some(fleet_core::time::now_unix() + 3600),
    )
    .await
    .unwrap();
    keys.create(
        s.tenant_id,
        user_id,
        "dead",
        &hash_token(dead),
        "nsk_dead",
        Some(fleet_core::time::now_unix() - 1),
    )
    .await
    .unwrap();

    assert_eq!(get_hosts_with(&s, &format!("Bearer {live}")).await, 200);
    assert_eq!(get_hosts_with(&s, &format!("Bearer {dead}")).await, 401);
}

#[tokio::test]
async fn keys_are_private_to_their_owner() {
    let s = start_http().await;
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
    let s = start_http().await;
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
