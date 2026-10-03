//! Encrypted bundles (enc-v1) end-to-end: register a key fingerprint, upload a
//! client-side-encrypted bundle, verify the server stores/signs/serves it opaquely and
//! refuses to read it, and that an agent holding the key — and only such an agent —
//! can open it.

mod common;

use common::{signup_login, start, TestServer};

use fleet_core::encbundle::BundleKey;

async fn enroll_a_host(s: &TestServer) -> (fleet_agent_sim::EnrolledAgent, String) {
    let r = s
        .cookie_jar
        .post(format!("{}/api/hosts", s.base_url))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = r.json().await.unwrap();
    let token = body["bootstrap_token"].as_str().unwrap().to_string();
    let host_id = body["host_id"].as_str().unwrap().to_string();

    let mut last = String::new();
    for _ in 0..20 {
        match fleet_agent_sim::enroll(&s.base_url, &token, Some("alpha"), Some("linux")).await {
            Ok(a) => return (a, host_id),
            Err(e) => last = format!("{e:?}"),
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("enroll never succeeded: {last}");
}

async fn upload_bundle(
    s: &TestServer,
    name: &str,
    version: &str,
    format: Option<&str>,
    bytes: Vec<u8>,
) -> reqwest::Response {
    let mut form = reqwest::multipart::Form::new()
        .text("name", name.to_string())
        .text("version", version.to_string())
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(bytes).file_name("bundle.bin"),
        );
    if let Some(f) = format {
        form = form.text("format", f.to_string());
    }
    s.cookie_jar
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn encrypted_bundle_end_to_end() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let (mut agent, host_id) = enroll_a_host(&s).await;

    // 1. No key registered yet.
    let r = s
        .cookie_jar
        .get(format!("{}/api/bundle-key", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert!(v["fingerprint"].is_null());

    // 2. Operator's browser generates a key and registers its fingerprint.
    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200, "{:?}", r.text().await);

    // 3. Encrypt client-side and upload as enc-v1.
    let secret_zip = b"PK\x03\x04-pretend-zip-with-secrets".to_vec();
    let blob = key.encrypt("secrets", "1.0.0", &secret_zip);
    let r = upload_bundle(&s, "secrets", "1.0.0", Some("enc-v1"), blob.clone()).await;
    assert_eq!(r.status(), 200, "upload: {:?}", r.text().await);
    let bundle: serde_json::Value = r.json().await.unwrap();
    let bundle_id = bundle["id"].as_str().unwrap().to_string();
    let expected_sha = bundle["sha256"].as_str().unwrap().to_string();
    let signature = bundle["signature"].as_str().unwrap().to_string();
    assert_eq!(bundle["format"], "enc-v1");
    assert_eq!(bundle["key_fingerprint"], key.fingerprint_hex().as_str());
    // The sha256 the server signs is over the ciphertext.
    let ct_sha = fleet_core::digest::sha256_hex(&blob);
    assert_eq!(expected_sha, ct_sha);

    // 4. The server cannot read it: config extraction and compose-from refuse.
    let r = s
        .cookie_jar
        .get(format!("{}/api/bundles/{bundle_id}/config", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409, "get_config must refuse encrypted bundles");
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({
            "name": "secrets", "version": "1.0.1",
            "config_json": {}, "base_bundle_id": bundle_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409, "compose must refuse an encrypted base");

    // 5. Nothing stored server-side contains the plaintext.
    let stored = std::fs::read(
        s._tempdir
            .path()
            .join("bundles")
            .join("1")
            .join(format!("{bundle_id}.zip")),
    )
    .unwrap();
    assert_eq!(stored, blob);
    assert!(!stored
        .windows(secret_zip.len())
        .any(|w| w == secret_zip.as_slice()));

    // 6. Assign via a group and let the agent pick it up.
    let g = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "all",
            "selector": { "clauses": [{"op": "eq", "key": "role", "value": "db"}] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(g.status(), 201);
    let group: serde_json::Value = g.json().await.unwrap();
    let group_id = group["id"].as_str().unwrap().to_string();
    let a = s
        .cookie_jar
        .post(format!("{}/api/groups/{group_id}/bundles", s.base_url))
        .json(&serde_json::json!({"bundle_id": bundle_id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), 204);

    // The operator places the host, not the host itself: this group carries secrets, and a
    // selector over operator tags is the only kind a compromised host cannot talk its way
    // into. See `fleet_core::selector`.
    let t = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/role", s.base_url, host_id))
        .json(&serde_json::json!({"value": "db"}))
        .send()
        .await
        .unwrap();
    assert_eq!(t.status(), 204);
    s.agent_limits.forget_last_poll(&host_id);
    let ds = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(ds.bundles.len(), 1);
    assert_eq!(ds.bundles[0]["format"], "enc-v1");

    // 7. Download: sha + signature verify against the ciphertext, exactly as for plain.
    let downloaded = agent
        .fetch_bundle_verified(ds.descriptor(&ds.bundles[0]).unwrap(), &signature)
        .await
        .unwrap();
    assert_eq!(downloaded, blob);

    // 8. Opening: fails without a key, with the wrong key, and under a substituted
    //    name/version; succeeds with the provisioned key.
    assert!(agent
        .open_bundle("secrets", "1.0.0", downloaded.clone())
        .is_err());
    agent.bundle_encryption_keys = vec![BundleKey::generate().to_b64()];
    let err = agent
        .open_bundle("secrets", "1.0.0", downloaded.clone())
        .unwrap_err();
    assert!(err.to_string().contains("no local key matches"), "{err}");
    agent.bundle_encryption_keys = vec![BundleKey::generate().to_b64(), key.to_b64()];
    assert!(
        agent
            .open_bundle("other-name", "1.0.0", downloaded.clone())
            .is_err(),
        "substituted identity must fail authentication"
    );
    let opened = agent
        .open_bundle("secrets", "1.0.0", downloaded.clone())
        .unwrap();
    assert_eq!(opened, secret_zip);

    // 9. require_encrypted_bundles: plain content is refused outright.
    agent.require_encrypted_bundles = true;
    assert!(agent
        .open_bundle("plain", "1.0.0", b"PK\x03\x04plain-zip".to_vec())
        .is_err());
    assert_eq!(
        agent.open_bundle("secrets", "1.0.0", downloaded).unwrap(),
        secret_zip
    );
}

#[tokio::test]
async fn encrypted_upload_validation() {
    let s = start().await;
    signup_login(&s, "beta", "bob@example.com").await;

    // enc-v1 flag with bytes that are not an NSEB1 envelope.
    let r = upload_bundle(
        &s,
        "x",
        "1",
        Some("enc-v1"),
        b"PK\x03\x04not-encrypted".to_vec(),
    )
    .await;
    assert_eq!(r.status(), 400, "{:?}", r.text().await);

    // Plain flag with bytes that carry the envelope magic — mislabeling is rejected both ways.
    let key = BundleKey::generate();
    let blob = key.encrypt("x", "1", b"zip");
    let r = upload_bundle(&s, "x", "1", None, blob).await;
    assert_eq!(r.status(), 400, "{:?}", r.text().await);

    // Unknown format value.
    let r = upload_bundle(&s, "x", "1", Some("enc-v9"), b"whatever".to_vec()).await;
    assert_eq!(r.status(), 400, "{:?}", r.text().await);

    // Bad fingerprints.
    for bad in ["", "zzzz", "0123456789abcde", "0123456789abcdef0"] {
        let r = s
            .cookie_jar
            .put(format!("{}/api/bundle-key", s.base_url))
            .json(&serde_json::json!({ "fingerprint": bad }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 400, "fingerprint {bad:?} must be rejected");
    }

    // Plain uploads keep working and report their format.
    let r = upload_bundle(&s, "x", "1", None, b"PK\x03\x04plain".to_vec()).await;
    assert_eq!(r.status(), 200);
    let v: serde_json::Value = r.json().await.unwrap();
    assert_eq!(v["format"], "plain");
    assert!(v["key_fingerprint"].is_null());
}

/// The operator-facing download endpoint that backs in-browser editing. The flow for an
/// encrypted bundle is download → decrypt → edit → re-encrypt → upload as a new version;
/// the first leg must return the stored bytes verbatim or nothing ever decrypts.
#[tokio::test]
async fn operator_download_round_trip() {
    let s = start().await;
    signup_login(&s, "gamma", "carol@example.com").await;

    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let plain_zip = b"PK\x03\x04-pretend-zip".to_vec();
    let blob = key.encrypt("sealed", "1.0.0", &plain_zip);
    let r = upload_bundle(&s, "sealed", "1.0.0", Some("enc-v1"), blob.clone()).await;
    assert_eq!(r.status(), 200, "upload: {:?}", r.text().await);
    let bundle: serde_json::Value = r.json().await.unwrap();
    let enc_id = bundle["id"].as_str().unwrap().to_string();

    // Encrypted: bytes come back verbatim, marked as an opaque attachment.
    let r = s
        .cookie_jar
        .get(format!("{}/api/bundles/{enc_id}/download", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()[reqwest::header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert!(r.headers()[reqwest::header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("sealed-1.0.0.nseb"));
    let body = r.bytes().await.unwrap().to_vec();
    assert_eq!(
        body, blob,
        "download must be the stored ciphertext, byte for byte"
    );
    let opened = key.decrypt("sealed", "1.0.0", &body).unwrap();
    assert_eq!(opened, plain_zip, "tenant key must open the download");

    // The browser's edit loop tail: re-encrypt under the new version and upload.
    let blob2 = key.encrypt("sealed", "1.0.1", b"PK\x03\x04-edited-zip");
    let r = upload_bundle(&s, "sealed", "1.0.1", Some("enc-v1"), blob2).await;
    assert_eq!(r.status(), 200, "re-upload: {:?}", r.text().await);

    // Plain: downloads as a zip.
    let plain_bytes = b"PK\x03\x04plain".to_vec();
    let r = upload_bundle(&s, "open", "1.0.0", None, plain_bytes.clone()).await;
    assert_eq!(r.status(), 200);
    let plain_id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = s
        .cookie_jar
        .get(format!("{}/api/bundles/{plain_id}/download", s.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(
        r.headers()[reqwest::header::CONTENT_TYPE],
        "application/zip"
    );
    assert!(r.headers()[reqwest::header::CONTENT_DISPOSITION]
        .to_str()
        .unwrap()
        .contains("open-1.0.0.zip"));
    assert_eq!(r.bytes().await.unwrap().to_vec(), plain_bytes);

    // Unknown id → 404.
    let r = s
        .cookie_jar
        .get(format!(
            "{}/api/bundles/no-such-bundle/download",
            s.base_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);
}

/// Stage one re-sealed encrypted version.
async fn stage(s: &TestServer, id: &str, bytes: Vec<u8>) -> reqwest::Response {
    s.cookie_jar
        .post(format!("{}/api/bundles/{id}/reseal", s.base_url))
        .header("content-type", "application/octet-stream")
        .body(bytes)
        .send()
        .await
        .unwrap()
}

async fn commit_rename(
    s: &TestServer,
    from: &str,
    to: &str,
    resealed: serde_json::Value,
) -> reqwest::Response {
    s.cookie_jar
        .post(format!("{}/api/bundles/rename", s.base_url))
        .json(&serde_json::json!({ "from": from, "to": to, "resealed": resealed }))
        .send()
        .await
        .unwrap()
}

/// Rename the way the browser does: stage each re-sealed version, then commit. Returns the
/// first refusal, from staging or from the commit.
async fn rename_bundle(
    s: &TestServer,
    from: &str,
    to: &str,
    sealed: Vec<(String, Vec<u8>)>,
) -> reqwest::Response {
    let mut resealed = serde_json::Map::new();
    for (id, bytes) in sealed {
        let r = stage(s, &id, bytes).await;
        if r.status() != 200 {
            return r;
        }
        let staged: serde_json::Value = r.json().await.unwrap();
        resealed.insert(id, staged["staged_id"].clone());
    }
    commit_rename(s, from, to, serde_json::Value::Object(resealed)).await
}

/// The orphan sweep, with no grace period.
async fn sweep_now(s: &TestServer) -> usize {
    fleet_server::housekeeping::sweep_bundle_files(&s.db, s.state.bundle_store.as_ref(), 0).await
}

/// Renaming moves every version of a name: plain versions keep their id, encrypted ones
/// are re-sealed by the client and swapped in under a new id, and either way the groups
/// keep carrying the same versions — which the agent then verifies and opens under the
/// new name.
#[tokio::test]
async fn rename_keeps_assignments_and_reseals_encrypted_versions() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let (mut agent, host_id) = enroll_a_host(&s).await;

    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);

    let plain_zip = b"PK\x03\x04-plain".to_vec();
    let r = upload_bundle(&s, "app", "1", None, plain_zip.clone()).await;
    assert_eq!(r.status(), 200);
    let plain: serde_json::Value = r.json().await.unwrap();
    let plain_id = plain["id"].as_str().unwrap().to_string();

    let secret_zip = b"PK\x03\x04-secret".to_vec();
    let r = upload_bundle(
        &s,
        "app",
        "2",
        Some("enc-v1"),
        key.encrypt("app", "2", &secret_zip),
    )
    .await;
    assert_eq!(r.status(), 200);
    let enc: serde_json::Value = r.json().await.unwrap();
    let enc_id = enc["id"].as_str().unwrap().to_string();

    let r = upload_bundle(&s, "taken", "1", None, b"PK\x03\x04-other".to_vec()).await;
    assert_eq!(r.status(), 200);

    let g = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "db",
            "selector": { "clauses": [{"op": "eq", "key": "role", "value": "db"}] }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(g.status(), 201);
    let group: serde_json::Value = g.json().await.unwrap();
    let group_id = group["id"].as_str().unwrap().to_string();
    for (id, priority) in [(&plain_id, 100), (&enc_id, 200)] {
        let a = s
            .cookie_jar
            .post(format!("{}/api/groups/{group_id}/bundles", s.base_url))
            .json(&serde_json::json!({"bundle_id": id, "priority": priority}))
            .send()
            .await
            .unwrap();
        assert_eq!(a.status(), 204);
    }
    let t = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/role", s.base_url, host_id))
        .json(&serde_json::json!({"value": "db"}))
        .send()
        .await
        .unwrap();
    assert_eq!(t.status(), 204);

    // The host is in sync before the rename: polling with its current hash is a 304.
    s.agent_limits.forget_last_poll(&host_id);
    let before = agent.fetch_desired_state(None).await.unwrap().unwrap();
    s.agent_limits.forget_last_poll(&host_id);
    assert!(agent
        .fetch_desired_state(Some(&before.state_hash))
        .await
        .unwrap()
        .is_none());

    // Refusals change nothing: an encrypted version without new ciphertext, a name in use,
    // a name that does not exist, a part for a version that is not encrypted.
    let r = rename_bundle(&s, "app", "web", vec![]).await;
    assert_eq!(r.status(), 400, "{:?}", r.text().await);
    let r = rename_bundle(
        &s,
        "app",
        "taken",
        vec![(enc_id.clone(), key.encrypt("taken", "2", &secret_zip))],
    )
    .await;
    assert_eq!(r.status(), 409);
    let r = rename_bundle(&s, "nope", "web", vec![]).await;
    assert_eq!(r.status(), 404);
    let r = rename_bundle(
        &s,
        "app",
        "web",
        vec![
            (enc_id.clone(), key.encrypt("web", "2", &secret_zip)),
            (plain_id.clone(), key.encrypt("web", "1", &plain_zip)),
        ],
    )
    .await;
    assert_eq!(r.status(), 400);

    let r = rename_bundle(
        &s,
        "app",
        "web",
        vec![(enc_id.clone(), key.encrypt("web", "2", &secret_zip))],
    )
    .await;
    assert_eq!(r.status(), 200, "{:?}", r.text().await);
    let renamed: Vec<serde_json::Value> = r.json().await.unwrap();
    assert_eq!(renamed.len(), 2);
    assert!(renamed.iter().all(|b| b["name"] == "web"));
    let id_of = |version: &str| {
        renamed.iter().find(|b| b["version"] == version).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let new_enc_id = id_of("2");
    // A plain version is renamed in place — same id, same bytes; only an encrypted one,
    // whose ciphertext had to change, moves to a new id.
    assert_eq!(id_of("1"), plain_id);
    assert_eq!(
        renamed.iter().find(|b| b["version"] == "1").unwrap()["sha256"],
        plain["sha256"]
    );
    assert_ne!(new_enc_id, enc_id);

    // Nothing is left under the old name, and the replaced ciphertext is gone from disk.
    let list: Vec<serde_json::Value> = s
        .cookie_jar
        .get(format!("{}/api/bundles", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(list.iter().all(|b| b["name"] != "app"));
    let dir = s._tempdir.path().join("bundles").join("1");
    // The replaced ciphertext stays until housekeeping, so an agent mid-download of it is
    // not cut off; so do the re-seals staged by the two refused attempts above. The sweep
    // takes those three and nothing a row points at.
    assert!(dir.join(format!("{enc_id}.zip")).exists());
    assert_eq!(sweep_now(&s).await, 3);
    assert!(!dir.join(format!("{enc_id}.zip")).exists());
    for id in [&plain_id, &new_enc_id] {
        assert!(dir.join(format!("{id}.zip")).exists());
    }

    // One audit entry per version, filed under the id it has now and naming the one it had.
    let mut ids: Vec<(String, String)> = sqlx::query_as::<_, (String, String)>(
        "SELECT target_id, metadata_json FROM audit_log WHERE action = 'bundle.renamed'
          AND metadata_json LIKE '%\"to\":\"web\"%'",
    )
    .fetch_all(&s.db.read)
    .await
    .unwrap()
    .into_iter()
    .map(|(target, meta)| {
        let meta: serde_json::Value = serde_json::from_str(&meta).unwrap();
        (meta["old_id"].as_str().unwrap().to_string(), target)
    })
    .collect();
    ids.sort();
    let mut want = vec![
        (plain_id.clone(), plain_id.clone()),
        (enc_id.clone(), new_enc_id.clone()),
    ];
    want.sort();
    assert_eq!(ids, want);

    // The group still carries both versions, with their priorities.
    let carried: Vec<serde_json::Value> = s
        .cookie_jar
        .get(format!("{}/api/groups/{group_id}/bundles", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut ids: Vec<(String, i64)> = carried
        .iter()
        .map(|b| {
            (
                b["bundle_id"].as_str().unwrap().to_string(),
                b["priority"].as_i64().unwrap(),
            )
        })
        .collect();
    ids.sort();
    let mut want = vec![(plain_id.clone(), 100), (new_enc_id.clone(), 200)];
    want.sort();
    assert_eq!(ids, want);

    // The host that was in sync is told something changed — polling with its old hash is
    // no longer a 304 — and sees the new name; the signatures verify against it, and the
    // re-sealed version opens under it.
    s.agent_limits.forget_last_poll(&host_id);
    let ds = agent
        .fetch_desired_state(Some(&before.state_hash))
        .await
        .unwrap()
        .expect("a rename must change the desired-state hash");
    assert_ne!(ds.state_hash, before.state_hash);
    assert_eq!(ds.bundles.len(), 2);
    agent.bundle_encryption_keys = vec![key.to_b64()];
    for b in &ds.bundles {
        assert_eq!(b["name"], "web");
        let signature = list.iter().find(|l| l["id"] == b["id"]).unwrap()["signature"]
            .as_str()
            .unwrap()
            .to_string();
        let bytes = agent
            .fetch_bundle_verified(ds.descriptor(b).unwrap(), &signature)
            .await
            .unwrap();
        if b["format"] == "enc-v1" {
            assert_eq!(agent.open_bundle("web", "2", bytes).unwrap(), secret_zip);
        } else {
            assert_eq!(bytes, plain_zip);
        }
    }
}

/// A bundle whose versions are all plain: the case where renaming in place left the
/// desired-state hash untouched (it covered ids, not names), so a host already in sync kept
/// getting 304s and never heard of the new name.
#[tokio::test]
async fn renaming_a_plain_bundle_reaches_hosts_already_in_sync() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let (agent, host_id) = enroll_a_host(&s).await;

    let r = upload_bundle(&s, "base", "1", None, b"PK\x03\x04-base".to_vec()).await;
    assert_eq!(r.status(), 200);
    let bundle: serde_json::Value = r.json().await.unwrap();
    let g: serde_json::Value = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": "all",
            "selector": { "clauses": [{"op": "eq", "key": "role", "value": "db"}] }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let a = s
        .cookie_jar
        .post(format!(
            "{}/api/groups/{}/bundles",
            s.base_url,
            g["id"].as_str().unwrap()
        ))
        .json(&serde_json::json!({"bundle_id": bundle["id"], "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), 204);
    let t = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/role", s.base_url, host_id))
        .json(&serde_json::json!({"value": "db"}))
        .send()
        .await
        .unwrap();
    assert_eq!(t.status(), 204);

    s.agent_limits.forget_last_poll(&host_id);
    let before = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(before.bundles[0]["name"], "base");

    let r = rename_bundle(&s, "base", "baseline", vec![]).await;
    assert_eq!(r.status(), 200, "{:?}", r.text().await);

    s.agent_limits.forget_last_poll(&host_id);
    let after = agent
        .fetch_desired_state(Some(&before.state_hash))
        .await
        .unwrap()
        .expect("a host in sync before the rename must be sent the renamed state, not a 304");
    assert_eq!(after.bundles[0]["name"], "baseline");
}

/// Upload a plain bundle, put it in a group the host is in, and return its id.
async fn assigned_plain_bundle(s: &TestServer, host_id: &str, name: &str, bytes: &[u8]) -> String {
    let r = upload_bundle(s, name, "1", None, bytes.to_vec()).await;
    assert_eq!(r.status(), 200);
    let id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let g: serde_json::Value = s
        .cookie_jar
        .post(format!("{}/api/groups", s.base_url))
        .json(&serde_json::json!({
            "name": format!("g-{name}"),
            "selector": { "clauses": [{"op": "eq", "key": "role", "value": "db"}] }
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let a = s
        .cookie_jar
        .post(format!(
            "{}/api/groups/{}/bundles",
            s.base_url,
            g["id"].as_str().unwrap()
        ))
        .json(&serde_json::json!({"bundle_id": id, "priority": 100}))
        .send()
        .await
        .unwrap();
    assert_eq!(a.status(), 204);
    let t = s
        .cookie_jar
        .put(format!("{}/api/hosts/{}/tags/role", s.base_url, host_id))
        .json(&serde_json::json!({"value": "db"}))
        .send()
        .await
        .unwrap();
    assert_eq!(t.status(), 204);
    id
}

/// A plain version is re-signed over the digest recorded at upload, never over whatever is
/// on disk now: bytes changed since then must still fail the agent's check after a rename,
/// not come out of it validly signed.
#[tokio::test]
async fn a_rename_never_vouches_for_bytes_changed_on_disk() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let (agent, host_id) = enroll_a_host(&s).await;
    let id = assigned_plain_bundle(&s, &host_id, "base", b"PK\x03\x04-original").await;

    let stored = s
        ._tempdir
        .path()
        .join("bundles")
        .join("1")
        .join(format!("{id}.zip"));
    std::fs::write(&stored, b"PK\x03\x04-tampered").unwrap();

    let r = rename_bundle(&s, "base", "baseline", vec![]).await;
    assert_eq!(r.status(), 200, "{:?}", r.text().await);

    s.agent_limits.forget_last_poll(&host_id);
    let ds = agent.fetch_desired_state(None).await.unwrap().unwrap();
    let b = &ds.bundles[0];
    assert_eq!(b["name"], "baseline");
    let err = agent
        .fetch_bundle_verified(ds.descriptor(b).unwrap(), b["signature"].as_str().unwrap())
        .await
        .expect_err("bytes changed on disk must not verify after a rename");
    assert!(err.to_string().to_lowercase().contains("sha"), "{err}");
}

/// A re-sealed version must be the same content sealed with the same key, as far as the
/// server can tell — and a refused rename leaves everything as it was.
#[tokio::test]
async fn a_resealed_version_must_match_the_original() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let zip = b"PK\x03\x04-secret".to_vec();
    let original = key.encrypt("app", "1", &zip);
    let r = upload_bundle(&s, "app", "1", Some("enc-v1"), original.clone()).await;
    assert_eq!(r.status(), 200);
    let id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    let other_key = BundleKey::generate();
    let mut longer = zip.clone();
    longer.push(b'!');
    for (what, parts) in [
        (
            "another key",
            vec![(id.clone(), other_key.encrypt("web", "1", &zip))],
        ),
        (
            "different content",
            vec![(id.clone(), key.encrypt("web", "1", &longer))],
        ),
        (
            "the original ciphertext sent back",
            vec![(id.clone(), original.clone())],
        ),
    ] {
        let r = rename_bundle(&s, "app", "web", parts).await;
        assert_eq!(r.status(), 400, "{what}: {:?}", r.text().await);
    }

    let list: Vec<serde_json::Value> = s
        .cookie_jar
        .get(format!("{}/api/bundles", s.base_url))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["id"], id.as_str());
    assert_eq!(list[0]["name"], "app");
    let dir = s._tempdir.path().join("bundles").join("1");
    let files: Vec<_> = std::fs::read_dir(&dir).unwrap().collect();
    assert_eq!(
        files.len(),
        1,
        "nothing a refused rename stored is left behind"
    );
}

/// `from` is matched exactly as stored, so a bundle whose name predates validation — the
/// kind most worth renaming — can be renamed.
#[tokio::test]
async fn a_bundle_with_a_legacy_name_can_be_renamed() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let r = upload_bundle(&s, "legacy", "1", None, b"PK\x03\x04-x".to_vec()).await;
    assert_eq!(r.status(), 200);
    sqlx::query("UPDATE bundles SET name = 'my bundle' WHERE name = 'legacy'")
        .execute(&s.db.write)
        .await
        .unwrap();

    let r = rename_bundle(&s, "my bundle", "my-bundle", vec![]).await;
    assert_eq!(r.status(), 200, "{:?}", r.text().await);
    let renamed: Vec<serde_json::Value> = r.json().await.unwrap();
    assert_eq!(renamed[0]["name"], "my-bundle");
}

/// The transaction itself refuses a picture of the bundle that is no longer true: a
/// version saved under the old name after the caller read them would be left behind, and a
/// name taken meanwhile is reported as that rather than as "changed".
#[tokio::test]
async fn the_rename_transaction_refuses_a_stale_picture() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    for v in ["1", "2"] {
        let r = upload_bundle(&s, "app", v, None, format!("PK\x03\x04-{v}").into_bytes()).await;
        assert_eq!(r.status(), 200);
    }
    let r = upload_bundle(&s, "taken", "1", None, b"PK\x03\x04-t".to_vec()).await;
    assert_eq!(r.status(), 200);
    let repo = fleet_storage::BundlesRepo::new(&s.db);
    let versions = repo.list_by_name(1, "app").await.unwrap();
    let only_first = vec![fleet_storage::RenamedInPlace {
        id: versions[0].id.clone(),
        signature: "sig".into(),
    }];

    assert_eq!(
        repo.rename(1, "app", "web", &only_first, &[])
            .await
            .unwrap(),
        fleet_storage::RenameOutcome::Changed
    );
    assert_eq!(
        repo.rename(1, "app", "taken", &only_first, &[])
            .await
            .unwrap(),
        fleet_storage::RenameOutcome::NameTaken
    );
    let still: Vec<String> = repo
        .list_by_name(1, "app")
        .await
        .unwrap()
        .into_iter()
        .map(|b| b.signature)
        .collect();
    assert_eq!(still.len(), 2, "a refused rename changes nothing");
    assert!(still.iter().all(|sig| sig != "sig"));
}

/// A staged id names a file, so the commit only accepts one the server could have minted
/// that no bundle row owns — not another bundle's file, not a path.
#[tokio::test]
async fn a_rename_only_commits_files_it_staged() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let zip = b"PK\x03\x04-secret".to_vec();
    let r = upload_bundle(
        &s,
        "app",
        "1",
        Some("enc-v1"),
        key.encrypt("app", "1", &zip),
    )
    .await;
    let enc_id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = upload_bundle(&s, "other", "1", None, b"PK\x03\x04-other".to_vec()).await;
    let other_id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    for staged in [
        other_id.as_str(),
        "../../1/whatever",
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",
    ] {
        let r = commit_rename(
            &s,
            "app",
            "web",
            serde_json::json!({ enc_id.clone(): staged }),
        )
        .await;
        assert_eq!(r.status(), 400, "staged id {staged}: {:?}", r.text().await);
    }
    // A key for something that is not an encrypted version of the bundle.
    let r = commit_rename(
        &s,
        "app",
        "web",
        serde_json::json!({ other_id.clone(): "x" }),
    )
    .await;
    assert_eq!(r.status(), 400);

    // An oversized body is refused while it is read — the server answers and stops reading,
    // so the client may see the 400 or the connection closing under it — and nothing is
    // staged.
    let sent = s
        .cookie_jar
        .post(format!("{}/api/bundles/{enc_id}/reseal", s.base_url))
        .header("content-type", "application/octet-stream")
        .body(vec![0u8; 1024 * 1024])
        .send()
        .await;
    if let Ok(r) = sent {
        assert_eq!(r.status(), 400);
    }
    assert_eq!(sweep_now(&s).await, 0);

    let r = rename_bundle(
        &s,
        "app",
        "web",
        vec![(enc_id.clone(), key.encrypt("web", "1", &zip))],
    )
    .await;
    assert_eq!(r.status(), 200, "{:?}", r.text().await);
}

/// Bundle files no row points at are swept once older than the grace period, and only
/// those: a staged re-seal is left alone while it is fresh.
#[tokio::test]
async fn the_sweep_removes_only_old_files_no_bundle_points_at() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let zip = b"PK\x03\x04-secret".to_vec();
    let r = upload_bundle(
        &s,
        "app",
        "1",
        Some("enc-v1"),
        key.encrypt("app", "1", &zip),
    )
    .await;
    let enc_id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = stage(&s, &enc_id, key.encrypt("web", "1", &zip)).await;
    assert_eq!(r.status(), 200);
    let staged = r.json::<serde_json::Value>().await.unwrap()["staged_id"]
        .as_str()
        .unwrap()
        .to_string();

    let store = s.state.bundle_store.as_ref();
    assert_eq!(
        fleet_server::housekeeping::sweep_bundle_files(&s.db, store, 3_600).await,
        0,
        "a fresh staged re-seal is waiting for its commit"
    );
    assert_eq!(sweep_now(&s).await, 1);
    let dir = s._tempdir.path().join("bundles").join("1");
    assert!(!dir.join(format!("{staged}.zip")).exists());
    assert!(dir.join(format!("{enc_id}.zip")).exists());

    // A commit naming a re-seal the sweep took asks for it again.
    let r = commit_rename(
        &s,
        "app",
        "web",
        serde_json::json!({ enc_id.clone(): staged }),
    )
    .await;
    assert_eq!(r.status(), 400);
    assert!(r.text().await.unwrap().contains("re-seal it again"));
}

/// An edit is saved against the bundle it was opened from. Once that bundle has been
/// renamed, the save is refused instead of recreating the old name beside the new one.
#[tokio::test]
async fn an_edit_open_across_a_rename_cannot_save_the_old_name() {
    let s = start().await;
    signup_login(&s, "acme", "alice@example.com").await;
    let key = BundleKey::generate();
    let r = s
        .cookie_jar
        .put(format!("{}/api/bundle-key", s.base_url))
        .json(&serde_json::json!({ "fingerprint": key.fingerprint_hex() }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    let r = upload_bundle(&s, "plain", "1", None, b"PK\x03\x04-p".to_vec()).await;
    let plain_id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();
    let zip = b"PK\x03\x04-secret".to_vec();
    let r = upload_bundle(
        &s,
        "sealed",
        "1",
        Some("enc-v1"),
        key.encrypt("sealed", "1", &zip),
    )
    .await;
    let enc_id = r.json::<serde_json::Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    assert_eq!(
        rename_bundle(&s, "plain", "plain2", vec![]).await.status(),
        200
    );
    assert_eq!(
        rename_bundle(
            &s,
            "sealed",
            "sealed2",
            vec![(enc_id.clone(), key.encrypt("sealed2", "1", &zip))]
        )
        .await
        .status(),
        200
    );

    // The server-composed save of a plain bundle: renamed in place, so the base is there
    // under its new name.
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles/compose", s.base_url))
        .json(&serde_json::json!({
            "name": "plain", "version": "2", "config_json": {}, "base_bundle_id": plain_id,
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 409);
    assert!(r.text().await.unwrap().contains("plain2"));

    // The browser-built save of an encrypted bundle: its base moved to a new id.
    let form = reqwest::multipart::Form::new()
        .text("name", "sealed")
        .text("version", "2")
        .text("format", "enc-v1")
        .text("base_bundle_id", enc_id.clone())
        .part(
            "bundle",
            reqwest::multipart::Part::bytes(key.encrypt("sealed", "2", &zip)).file_name("b.nseb"),
        );
    let r = s
        .cookie_jar
        .post(format!("{}/api/bundles", s.base_url))
        .multipart(form)
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), 404);

    let names: Vec<String> = s
        .cookie_jar
        .get(format!("{}/api/bundles", s.base_url))
        .send()
        .await
        .unwrap()
        .json::<Vec<serde_json::Value>>()
        .await
        .unwrap()
        .iter()
        .map(|b| b["name"].as_str().unwrap().to_string())
        .collect();
    assert!(!names.contains(&"plain".to_string()) && !names.contains(&"sealed".to_string()));
}
