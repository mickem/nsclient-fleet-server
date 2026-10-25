//! Exporting groups and bundles as a configuration directory, and importing one back.

mod common;

use common::{signup_login, start, TestServer};
use fleet_core::crypto::encbundle::BundleKey;
use fleet_server::config_source;
use serde_json::{json, Value};

async fn get(s: &TestServer, path: &str) -> Value {
    let r = s
        .cookie_jar
        .get(format!("{}{path}", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "GET {path}");
    r.json().await.unwrap()
}

fn ids_by_label(bundles: &Value) -> std::collections::HashMap<String, String> {
    bundles
        .as_array()
        .unwrap()
        .iter()
        .map(|b| {
            (
                format!(
                    "{}@{}",
                    b["name"].as_str().unwrap(),
                    b["version"].as_str().unwrap()
                ),
                b["id"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

/// Configure in the UI, export, and load the export back — into the same database without
/// changing anything, and into a fresh one to the same result.
#[tokio::test]
async fn an_export_imports_back_to_the_same_configuration() {
    let s = start().await;
    signup_login(&s, "acme", "ops@acme.test").await;
    let c = &s.cookie_jar;
    let base = &s.base_url;

    // A composed bundle with scripts, a raw upload that is not a zip, and a sealed one.
    let r = c
        .post(format!("{base}/api/bundles/compose"))
        .json(&json!({
            "name": "base",
            "version": "1.0",
            "config_json": { "settings": { "x": "1" } },
            "scripts": [{ "path": "scripts/check.sh", "content_b64": "ZWNobyBvaw==" }],
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 201);
    let upload = |name: &str, format: &str, bytes: Vec<u8>| {
        let form = reqwest::multipart::Form::new()
            .text("name", name.to_string())
            .text("version", "1")
            .text("format", format.to_string())
            .part(
                "bundle",
                reqwest::multipart::Part::bytes(bytes).file_name("b"),
            );
        c.post(format!("{base}/api/bundles")).multipart(form).send()
    };
    assert_eq!(
        upload("raw", "plain", b"not a zip".to_vec())
            .await
            .unwrap()
            .status(),
        200
    );
    let sealed = BundleKey::generate().encrypt("sealed", "1", b"PK-zip");
    assert_eq!(
        upload("sealed", "enc-v1", sealed).await.unwrap().status(),
        200
    );

    let group: Value = c
        .post(format!("{base}/api/groups"))
        .json(&json!({ "name": "SQL Servers", "selector": { "clauses": [
            { "op": "eq", "key": "role", "value": "db" }
        ] } }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ids = ids_by_label(&get(&s, "/api/bundles").await);
    for (label, priority) in [("base@1.0", 10), ("sealed@1", 100)] {
        let r = c
            .post(format!(
                "{base}/api/groups/{}/bundles",
                group["id"].as_str().unwrap()
            ))
            .json(&json!({ "bundle_id": ids[label], "priority": priority }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 204);
    }

    let out = tempfile::TempDir::new().unwrap();
    let tenant_id = get(&s, "/api/me").await["tenant_id"].as_i64().unwrap();
    let report = config_source::export(&s.db, s.state.bundle_store.as_ref(), tenant_id, out.path())
        .await
        .unwrap();
    assert_eq!(report.groups, 1);
    assert_eq!(report.bundles_as_files, 1);
    assert_eq!(report.bundles_as_zip, 1, "{:?}", report.notes);
    assert_eq!(report.bundles_encrypted, 1);
    assert!(out
        .path()
        .join("bundles/base/1.0/scripts/check.sh")
        .is_file());
    assert!(out.path().join("bundles/raw/1.zip").is_file());
    assert!(out.path().join("bundles/sealed/1.nseb").is_file());
    let exported: Value =
        serde_json::from_slice(&std::fs::read(out.path().join("groups/sql-servers.json")).unwrap())
            .unwrap();
    assert_eq!(exported["name"], "SQL Servers");
    assert_eq!(
        exported["bundles"][0],
        json!({ "name": "base", "version": "1.0", "priority": 10 })
    );

    // A second export into the same place is refused rather than merged.
    assert!(
        config_source::export(&s.db, s.state.bundle_store.as_ref(), tenant_id, out.path())
            .await
            .is_err()
    );

    // Back into the database it came from: nothing to do, so agents re-download nothing.
    let master_key = &s.state.config.master_key;
    let report = config_source::reconcile(
        &s.db,
        s.state.bundle_store.as_ref(),
        master_key,
        tenant_id,
        out.path(),
        false,
    )
    .await
    .unwrap();
    assert!(!report.changed, "{report:?}");
    assert_eq!(ids_by_label(&get(&s, "/api/bundles").await), ids);

    // Into a fresh server: the same configuration, under new ids.
    let fresh = start().await;
    signup_login(&fresh, "other", "ops@other.test").await;
    let fresh_tenant = get(&fresh, "/api/me").await["tenant_id"].as_i64().unwrap();
    let report = config_source::reconcile(
        &fresh.db,
        fresh.state.bundle_store.as_ref(),
        &fresh.state.config.master_key,
        fresh_tenant,
        out.path(),
        false,
    )
    .await
    .unwrap();
    assert_eq!(report.bundles_added.len(), 3);
    assert_eq!(report.groups_added, ["SQL Servers"]);
    let imported = ids_by_label(&get(&fresh, "/api/bundles").await);
    let mut labels: Vec<_> = imported.keys().cloned().collect();
    labels.sort();
    assert_eq!(labels, ["base@1.0", "raw@1", "sealed@1"]);
    let groups = get(&fresh, "/api/groups").await;
    assert_eq!(groups[0]["selector"], group["selector"]);
    let assigned = get(
        &fresh,
        &format!("/api/groups/{}/bundles", groups[0]["id"].as_str().unwrap()),
    )
    .await;
    assert_eq!(assigned.as_array().unwrap().len(), 2);
}
