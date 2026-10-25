//! Groups and bundles from a configuration directory (`CONFIG_SOURCE_DIR`), and the export
//! and import that move an install into and out of one.

mod common;

use std::path::Path;
use std::sync::Arc;

use common::{enroll_a_host, signup_login, start, start_with, TestServer};
use fleet_core::crypto::encbundle::BundleKey;
use fleet_server::config_source::{self, ConfigSource};
use serde_json::{json, Value};

fn write(root: &Path, rel: &str, data: &[u8]) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, data).unwrap();
}

fn group_file(name: &str, bundles: Value) -> Vec<u8> {
    serde_json::to_vec_pretty(&json!({
        "name": name,
        "selector": { "clauses": [] },
        "bundles": bundles,
    }))
    .unwrap()
}

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

async fn reload(s: &TestServer, body: Value) -> (u16, Value) {
    let r = s
        .cookie_jar
        .post(format!("{}/api/config-source/reload", s.base_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    (status, r.json().await.unwrap_or(Value::Null))
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

/// A server whose first tenant's configuration lives in `dir`. Tenant ids start at 1 on a
/// fresh database, and the first sign-up creates that tenant.
async fn managed_server(dir: &Path) -> TestServer {
    let dir = dir.to_path_buf();
    let s = start_with(move |state| {
        state.config_source = Some(Arc::new(ConfigSource::new(dir, 1)));
    })
    .await;
    signup_login(&s, "acme", "ops@acme.test").await;
    assert_eq!(get(&s, "/api/me").await["tenant_id"], 1);
    s
}

#[tokio::test]
async fn a_directory_is_applied_kept_in_step_and_never_half_applied() {
    let cfg = tempfile::TempDir::new().unwrap();
    let root = cfg.path();
    write(
        root,
        "bundles/base/1/config.json",
        br#"{"settings":{"a":"1"}}"#,
    );
    write(
        root,
        "bundles/base/1/scripts/check.ps1",
        b"Write-Output 'ok'",
    );
    let key = BundleKey::generate();
    let sealed = key.encrypt("secrets", "1", b"PK-secret-zip");
    write(root, "bundles/secrets/1.nseb", &sealed);
    write(
        root,
        "groups/all.json",
        &group_file(
            "all",
            json!([
                { "name": "base", "version": "1", "priority": 50 },
                { "name": "secrets", "version": "1" },
            ]),
        ),
    );

    let s = managed_server(root).await;
    assert_eq!(get(&s, "/api/me").await["config_managed"], true);

    // First load: everything is new.
    let (status, report) = reload(&s, json!({})).await;
    assert_eq!(status, 200, "{report}");
    assert_eq!(report["changed"], true);
    assert_eq!(report["bundles_added"], json!(["base@1", "secrets@1"]));
    assert_eq!(report["groups_added"], json!(["all"]));

    let bundles = get(&s, "/api/bundles").await;
    let ids = ids_by_label(&bundles);
    assert_eq!(ids.len(), 2);
    let groups = get(&s, "/api/groups").await;
    let group_id = groups[0]["id"].as_str().unwrap().to_string();
    let assigned = get(&s, &format!("/api/groups/{group_id}/bundles")).await;
    assert_eq!(assigned.as_array().unwrap().len(), 2);

    // An agent receives both, signed by the tenant key like any uploaded bundle.
    let agent = enroll_a_host(&s).await;
    let ds = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(ds.bundles.len(), 2);
    for b in &ds.bundles {
        let bytes = agent
            .fetch_bundle_verified(ds.descriptor(b).unwrap(), b["signature"].as_str().unwrap())
            .await
            .unwrap();
        if b["name"] == "secrets" {
            assert_eq!(
                bytes, sealed,
                "an encrypted bundle is served exactly as committed"
            );
        }
    }

    // Nothing changed on disk: nothing changes in the database.
    let version_before = fleet_storage::TenantRepo::new(&s.db)
        .get(1)
        .await
        .unwrap()
        .unwrap()
        .config_version;
    let (status, report) = reload(&s, json!({})).await;
    assert_eq!(status, 200);
    assert_eq!(report["changed"], false, "{report}");
    let version_after = fleet_storage::TenantRepo::new(&s.db)
        .get(1)
        .await
        .unwrap()
        .unwrap()
        .config_version;
    assert_eq!(
        version_before, version_after,
        "an unchanged reload must not bump"
    );

    // One script edited: that version is replaced, the other keeps its id.
    write(
        root,
        "bundles/base/1/scripts/check.ps1",
        b"Write-Output 'changed'",
    );
    let (_, report) = reload(&s, json!({})).await;
    assert_eq!(report["bundles_replaced"], json!(["base@1"]));
    assert_eq!(report["bundles_unchanged"], 1);
    let after = ids_by_label(&get(&s, "/api/bundles").await);
    assert_ne!(after["base@1"], ids["base@1"]);
    assert_eq!(after["secrets@1"], ids["secrets@1"]);
    let groups = get(&s, "/api/groups").await;
    assert_eq!(
        groups[0]["id"], group_id,
        "a group keeps its id across reloads"
    );

    // A broken directory changes nothing, reports every problem, and is remembered.
    write(
        root,
        "groups/broken.json",
        &group_file("broken", json!([{ "name": "missing", "version": "9" }])),
    );
    write(root, "bundles/base/2/config.json", b"not json");
    let (status, body) = reload(&s, json!({})).await;
    assert_eq!(status, 422);
    let errors = body["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 2, "{body}");
    assert_eq!(ids_by_label(&get(&s, "/api/bundles").await), after);
    let st = get(&s, "/api/config-source").await;
    assert_eq!(st["managed"], true);
    assert_eq!(st["last"]["ok"], false);
    std::fs::remove_file(root.join("groups/broken.json")).unwrap();
    std::fs::remove_dir_all(root.join("bundles/base/2")).unwrap();

    // A dry run says what would happen and does none of it.
    std::fs::remove_file(root.join("bundles/secrets/1.nseb")).unwrap();
    write(
        root,
        "groups/all.json",
        &group_file("all", json!([{ "name": "base", "version": "1" }])),
    );
    let (_, report) = reload(&s, json!({ "dry_run": true })).await;
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["bundles_removed"], json!(["secrets@1"]));
    assert_eq!(report["assignments_changed"], true);
    assert_eq!(get(&s, "/api/bundles").await.as_array().unwrap().len(), 2);
    let (_, report) = reload(&s, json!({})).await;
    assert_eq!(report["bundles_removed"], json!(["secrets@1"]));
    assert_eq!(get(&s, "/api/bundles").await.as_array().unwrap().len(), 1);
    assert_eq!(get(&s, "/api/config-source").await["last"]["ok"], true);
}

#[tokio::test]
async fn the_api_cannot_edit_what_the_directory_owns() {
    let cfg = tempfile::TempDir::new().unwrap();
    write(cfg.path(), "bundles/base/1/config.json", b"{}");
    write(cfg.path(), "groups/all.json", &group_file("all", json!([])));
    let s = managed_server(cfg.path()).await;
    let (status, _) = reload(&s, json!({})).await;
    assert_eq!(status, 200);
    let bundle_id = get(&s, "/api/bundles").await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let group_id = get(&s, "/api/groups").await[0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    let c = &s.cookie_jar;
    let base = &s.base_url;
    let refused = [
        c.post(format!("{base}/api/groups"))
            .json(&json!({ "name": "x", "selector": { "clauses": [] } })),
        c.patch(format!("{base}/api/groups/{group_id}"))
            .json(&json!({ "name": "y" })),
        c.delete(format!("{base}/api/groups/{group_id}")),
        c.post(format!("{base}/api/groups/{group_id}/bundles"))
            .json(&json!({ "bundle_id": bundle_id })),
        c.delete(format!("{base}/api/groups/{group_id}/bundles/{bundle_id}")),
        c.post(format!("{base}/api/bundles/compose")).json(&json!({
            "name": "n", "version": "1", "config_json": {}
        })),
        c.post(format!("{base}/api/bundles/rename"))
            .json(&json!({ "from": "base", "to": "other" })),
        c.delete(format!("{base}/api/bundles/{bundle_id}")),
    ];
    for req in refused {
        let r = req.send().await.unwrap();
        assert_eq!(r.status(), 409);
        assert!(r.text().await.unwrap().contains("CONFIG_SOURCE_DIR"));
    }
    // Reads still work, and the directory's view is untouched.
    assert_eq!(get(&s, "/api/groups").await.as_array().unwrap().len(), 1);
    assert_eq!(get(&s, "/api/bundles").await.as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn reload_is_refused_when_no_directory_is_configured() {
    let s = start().await;
    signup_login(&s, "acme", "ops@acme.test").await;
    let (status, _) = reload(&s, json!({})).await;
    assert_eq!(status, 409);
    let st = get(&s, "/api/config-source").await;
    assert_eq!(st["managed"], false);
    assert_eq!(get(&s, "/api/me").await["config_managed"], false);
}

/// The migration path: configure in the UI, export, and load the export back — into the
/// same database without changing anything, and into a fresh one to the same result.
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
