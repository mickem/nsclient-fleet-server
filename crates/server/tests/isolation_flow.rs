//! Phase 7 — multi-tenancy hardening. Comprehensive cross-tenant isolation probes plus
//! trial-expiry behavior.

mod common;

use common::{complete_exchange, start, TestServer};

fn fresh_client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

async fn signup_and_login(s: &TestServer, c: &reqwest::Client, slug: &str, email: &str) {
    c.post(format!("{}/api/auth/signup", s.base_url))
        .json(&serde_json::json!({
            "email": email,
            "tenant_slug": slug,
            "tenant_name": slug.to_uppercase(),
            "turnstile_token": "",
        }))
        .send()
        .await
        .unwrap();

    let tenants = fleet_storage::TenantRepo::new(&s.db);
    let users = fleet_storage::UserRepo::new(&s.db);
    let links = fleet_storage::MagicLinkRepo::new(&s.db);
    let t = tenants.get_by_slug(slug).await.unwrap().unwrap();
    let u = users.find_by_email(email).await.unwrap().unwrap();
    let token = format!("magic-{slug}-XXXXXXXX");
    let hash = fleet_core::digest::sha256_hex(token.as_bytes());
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();
    let _ = complete_exchange(c, &s.base_url, &token).await;
}

struct Provisioned {
    host_id: String,
    group_id: String,
    bundle_id: String,
}

async fn provision(s: &TestServer, c: &reqwest::Client) -> Provisioned {
    // Host
    let host = c
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let host_id = host["host_id"].as_str().unwrap().to_string();

    // Group
    let group = c
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "g1",
            "selector": { "clauses": [] }
        }))
        .send()
        .await
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .unwrap();
    let group_id = group["id"].as_str().unwrap().to_string();

    // Bundle
    let form = reqwest::multipart::Form::new()
        .text("name", "b1")
        .text("version", "1.0")
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(b"opaque-bytes".to_vec())
                .file_name("b.zip")
                .mime_str("application/zip")
                .unwrap(),
        );
    let bundle: serde_json::Value = c
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bundle_id = bundle["id"].as_str().unwrap().to_string();

    Provisioned {
        host_id,
        group_id,
        bundle_id,
    }
}

#[tokio::test]
async fn cross_tenant_access_is_denied_everywhere() {
    let s = start().await;
    let ca = fresh_client();
    let cb = fresh_client();
    signup_and_login(&s, &ca, "alpha", "a@example.com").await;
    signup_and_login(&s, &cb, "beta", "b@example.com").await;
    let pa = provision(&s, &ca).await;
    let pb = provision(&s, &cb).await;

    // Sanity: each session can read its own
    let own = cb
        .get(format!("{}/api/hosts/{}", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(own.status(), 200);

    // -- Probes from A's session against B's resources -------------------------------
    // host detail
    let r = ca
        .get(format!("{}/api/hosts/{}", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "detail: A must not see B's host");

    // tag write
    let r = ca
        .put(format!("{}/api/hosts/{}/tags/role", s.base_url, pb.host_id))
        .json(&serde_json::json!({"value": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "tag put: A must not target B's host");

    // tag delete
    let r = ca
        .delete(format!("{}/api/hosts/{}/tags/role", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "tag delete");

    // override write
    let r = ca
        .put(format!("{}/api/hosts/{}/override", s.base_url, pb.host_id))
        .json(&serde_json::json!({"patch": {"x": 1}}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "override put: A must not target B's host");

    // override delete
    let r = ca
        .delete(format!("{}/api/hosts/{}/override", s.base_url, pb.host_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "override delete");

    // group patch
    let r = ca
        .patch(format!("{}/api/groups/{}", s.base_url, pb.group_id))
        .json(&serde_json::json!({"name": "hijacked"}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "group patch");

    // group delete
    let r = ca
        .delete(format!("{}/api/groups/{}", s.base_url, pb.group_id))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "group delete");

    // assign A's bundle to B's group (NOT FOUND because the group isn't A's)
    let r = ca
        .post(format!("{}/api/groups/{}/bundles", s.base_url, pb.group_id))
        .json(&serde_json::json!({"bundle_id": pa.bundle_id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "cross-group assignment");

    // assign B's bundle to A's group (NOT FOUND because the bundle isn't A's)
    let r = ca
        .post(format!("{}/api/groups/{}/bundles", s.base_url, pa.group_id))
        .json(&serde_json::json!({"bundle_id": pb.bundle_id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404, "cross-bundle assignment");

    // Listing groups from A's session must not include B's group
    let groups: Vec<serde_json::Value> = ca
        .get(format!("{}/api/groups", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids: Vec<&str> = groups.iter().filter_map(|g| g["id"].as_str()).collect();
    assert!(ids.contains(&pa.group_id.as_str()));
    assert!(!ids.contains(&pb.group_id.as_str()));

    // Listing bundles
    let bundles: Vec<serde_json::Value> = ca
        .get(format!("{}/api/bundles", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bids: Vec<&str> = bundles.iter().filter_map(|b| b["id"].as_str()).collect();
    assert!(bids.contains(&pa.bundle_id.as_str()));
    assert!(!bids.contains(&pb.bundle_id.as_str()));
}

#[tokio::test]
async fn expired_trial_returns_402_except_allowlisted() {
    let s = start().await;
    let c = fresh_client();
    signup_and_login(&s, &c, "tex", "t@example.com").await;

    // Force expiry directly in the DB
    sqlx::query("UPDATE tenants SET trial_expires_at = ? WHERE slug = 'tex'")
        .bind(fleet_core::time::now_unix() - 3600)
        .execute(&s.db.write)
        .await
        .unwrap();

    // /api/me works (allowlisted) and reports trial_expired: true
    let me_resp = c
        .get(format!("{}/api/me", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(me_resp.status(), 200);
    let me: serde_json::Value = me_resp.json().await.unwrap();
    assert_eq!(me["trial_expired"], true);

    // Other API routes return 402
    let r = c
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 402);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"], "trial_expired");

    let r = c
        .get(format!("{}/api/groups", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 402);

    // Logout still works (allowlisted)
    let r = c
        .post(format!("{}/api/auth/logout", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 204);
}

#[tokio::test]
async fn paid_or_unlimited_tenants_unaffected_by_expiry_check() {
    let s = start().await;
    let c = fresh_client();
    signup_and_login(&s, &c, "paid", "p@example.com").await;

    // No trial_expires_at → never expires (e.g. paid customers, on-prem)
    sqlx::query("UPDATE tenants SET trial_expires_at = NULL WHERE slug = 'paid'")
        .execute(&s.db.write)
        .await
        .unwrap();

    let r = c
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
}
