//! Encrypted bundles (enc-v1) end-to-end: register a key fingerprint, upload a
//! client-side-encrypted bundle, verify the server stores/signs/serves it opaquely and
//! refuses to read it, and that an agent holding the key — and only such an agent —
//! can open it.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use fleet_core::aead::MasterKey;
use fleet_core::encbundle::BundleKey;
use fleet_storage::Db;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

struct TestServer {
    base_url: String,
    _tempdir: TempDir,
    handles: Vec<tokio::task::JoinHandle<()>>,
    db: Db,
    agent_limits: fleet_server::agent_limits::AgentRateLimits,
    cookie_jar: reqwest::Client,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            h.abort();
        }
    }
}

async fn start() -> TestServer {
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("test.db");
    let bundle_dir = dir.path().join("bundles");

    let db = fleet_storage::open(&db_path).await.unwrap();
    fleet_storage::run_migrations(&db.write).await.unwrap();

    let http_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mtls_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let http_addr = http_listener.local_addr().unwrap();
    let mtls_addr = mtls_listener.local_addr().unwrap();

    let base_url = format!("http://{http_addr}");

    let key_b64 = MasterKey::generate_b64();
    std::env::set_var("MASTER_KEY", &key_b64);
    let master_key = MasterKey::from_b64(&key_b64).unwrap();
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bootstrap_jwt_secret = STANDARD.decode(&key_b64).unwrap();

    let cfg = fleet_server::config::Config {
        listen: format!("127.0.0.1:{}", http_addr.port()),
        listen_https: "127.0.0.1:0".into(),
        listen_mtls: format!("127.0.0.1:{}", mtls_addr.port()),
        agent_mtls_url: format!("https://127.0.0.1:{}", mtls_addr.port()),
        acme: None,
        database_path: PathBuf::from(&db_path),
        base_url: base_url.clone(),
        on_prem: false,
        on_prem_admin_email: None,
        on_prem_admin_password: None,
        platform_admin_emails: Vec::new(),
        magic_link_ttl_secs: 900,
        session_ttl_secs: 3600,
        bootstrap_ttl_secs: 3600,
        host_lost_after_secs: 172_800,
        client_cert_lifetime_days: 90,
        cookie_secure: false,
        daily_email_budget: 1_000_000,
        smtp: None,
        turnstile_secret: None,
        master_key,
        bootstrap_jwt_secret,
    };

    let (mtls_cert_pem, mtls_key_pem) =
        fleet_server::mtls::generate_self_signed_server("127.0.0.1").unwrap();

    let email = fleet_server::auth::email::EmailSender::from_config(cfg.smtp.as_ref()).unwrap();
    let turnstile =
        fleet_server::auth::turnstile::Turnstile::from_secret(cfg.turnstile_secret.clone());
    let rate_limits = fleet_server::auth::rate_limit::AuthRateLimits::new(cfg.daily_email_budget);
    let agent_limits = fleet_server::agent_limits::AgentRateLimits::new();
    let trust_store =
        fleet_server::mtls::MtlsContext::load(db.clone(), mtls_cert_pem.clone(), mtls_key_pem)
            .await
            .unwrap();
    let bundle_store: Arc<dyn fleet_server::bundles::BundleStore> =
        Arc::new(fleet_server::bundles::LocalBundleStore::new(bundle_dir));

    let agent_limits_handle = agent_limits.clone();
    let state = fleet_server::AppState {
        db: db.clone(),
        config: cfg.clone(),
        email,
        turnstile,
        rate_limits,
        agent_limits,
        enrollment_limits: fleet_server::agent_limits::EnrollmentLimits::default(),
        trust_store: trust_store.clone(),
        mtls_server_cert_pem: Arc::new(mtls_cert_pem),
        bundle_store,
        desired_state_cache: Default::default(),
    };

    let mtls_state = state.clone();
    let mtls_handle = tokio::spawn(async move {
        let r = fleet_server::mtls_router(mtls_state.clone());
        let _ = fleet_server::mtls::serve_on(mtls_listener, mtls_state.trust_store, r).await;
    });

    let app = fleet_server::router(state);
    let http_handle = tokio::spawn(async move {
        let _ = axum::serve(
            http_listener,
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

    TestServer {
        base_url,
        _tempdir: dir,
        handles: vec![http_handle, mtls_handle],
        db,
        agent_limits: agent_limits_handle,
        cookie_jar: reqwest::Client::builder()
            .cookie_store(true)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap(),
    }
}

async fn signup_login(s: &TestServer, slug: &str, email: &str) {
    s.cookie_jar
        .post(format!("{}/api/auth/signup", s.base_url))
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
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    let hash: String = h.finalize().iter().map(|b| format!("{b:02x}")).collect();
    links
        .create(&hash, t.id, u.id, fleet_core::time::now_unix() + 600)
        .await
        .unwrap();
    let _ = complete_exchange(&s.cookie_jar, &s.base_url, &token).await;
}

async fn complete_exchange(c: &reqwest::Client, base_url: &str, token: &str) -> reqwest::Response {
    let page = c
        .get(format!("{base_url}/api/auth/exchange?t={token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(page.status(), 200, "confirmation page must render on GET");
    let html = page.text().await.unwrap();
    let marker = "name=\"csrf\" value=\"";
    let start = html.find(marker).expect("csrf field present") + marker.len();
    let end = html[start..].find('"').expect("csrf value terminated");
    let csrf = html[start..start + end].to_string();
    c.post(format!("{base_url}/api/auth/exchange"))
        .form(&[("t", token), ("csrf", csrf.as_str())])
        .send()
        .await
        .unwrap()
}

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
    let ct_sha: String = Sha256::digest(&blob)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
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

    let mut tags = BTreeMap::new();
    tags.insert("role".into(), "db".into());
    agent.report_state(None, tags).await.unwrap();
    s.agent_limits.forget_last_poll(&host_id);
    let ds = agent.fetch_desired_state(None).await.unwrap().unwrap();
    assert_eq!(ds.bundles.len(), 1);
    assert_eq!(ds.bundles[0]["format"], "enc-v1");

    // 7. Download: sha + signature verify against the ciphertext, exactly as for plain.
    let downloaded = agent
        .fetch_bundle(&bundle_id, &expected_sha, &signature)
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
