//! Where a tenant may point explanations, on a server that has not allowed private endpoints.
//!
//! A binary of its own: `LLM_ALLOW_PRIVATE_ENDPOINTS` is process-wide, `failure_flow` turns
//! it on to reach its stub provider on loopback, and here it has to be off — the default,
//! and what a shared install runs with.

mod common;

use common::{signup_login, start, TestServer};

async fn put(s: &TestServer, body: serde_json::Value) -> (u16, String) {
    let r = s
        .cookie_jar
        .put(format!("{}/api/settings/explain", s.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    (r.status().as_u16(), r.text().await.unwrap())
}

#[tokio::test]
async fn a_tenant_cannot_point_explanations_inside_the_servers_network() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;

    for base_url in [
        "http://127.0.0.1:11434",
        "http://169.254.169.254/latest/meta-data",
        "http://10.0.0.5:8080/v1",
        "http://[::1]:8080/v1",
        "http://2130706433/v1",
    ] {
        let (status, body) = put(
            &s,
            serde_json::json!({
                "explain_enabled": true, "provider": "openai", "model": "m",
                "base_url": base_url, "api_key": "sk-test-key",
            }),
        )
        .await;
        assert_eq!(status, 400, "{base_url} was accepted: {body}");
        assert!(body.contains("not on the public internet"), "{body}");
    }

    // `ollama` with no base URL is this server's own loopback.
    let (status, body) = put(
        &s,
        serde_json::json!({ "explain_enabled": true, "provider": "ollama", "model": "llama3.1" }),
    )
    .await;
    assert_eq!(
        status, 400,
        "the default Ollama address was accepted: {body}"
    );

    // A public endpoint is what the setting is for.
    let (status, body) = put(
        &s,
        serde_json::json!({
            "explain_enabled": true, "provider": "openai", "model": "m",
            "base_url": "https://api.openai.com/v1", "api_key": "sk-test-key",
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
}

#[tokio::test]
async fn a_private_endpoint_already_stored_is_not_called() {
    // Settings saved while private endpoints were allowed, on a server that no longer
    // allows them: the check is made again when an explanation is asked for.
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let (status, body) = put(
        &s,
        serde_json::json!({
            "explain_enabled": true, "provider": "openai", "model": "m",
            "base_url": "https://api.openai.com/v1", "api_key": "sk-test-key",
        }),
    )
    .await;
    assert_eq!(status, 200, "{body}");
    sqlx::query("UPDATE tenant_failure_settings SET base_url = 'http://127.0.0.1:9/v1'")
        .execute(&s.db.write)
        .await
        .unwrap();
    sqlx::query("INSERT INTO hosts (id, tenant_id, hostname, created_at) SELECT 'h1', id, 'alpha', 0 FROM tenants")
        .execute(&s.db.write)
        .await
        .unwrap();

    let r = s
        .cookie_jar
        .post(format!("{}/api/explain", s.base_url))
        .json(&serde_json::json!({ "host": "h1", "error": "disk full" }))
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body = r.text().await.unwrap();
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("not on the public internet"), "{body}");

    let calls: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(calls), 0) FROM llm_usage")
        .fetch_one(&s.db.read)
        .await
        .unwrap();
    assert_eq!(calls, 0, "a refused endpoint is not an attempt");
}
