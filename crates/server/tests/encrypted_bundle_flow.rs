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
