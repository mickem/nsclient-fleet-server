use std::time::{SystemTime, UNIX_EPOCH};

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::tier;
use fleet_core::time::now_unix;
use fleet_enrollment::{encode_bootstrap, BootstrapClaims};
use fleet_storage::{HostOverridesRepo, HostRepo, HostTagsRepo, TenantRepo};
use serde::{Deserialize, Serialize};

use crate::auth::tokens::{hash_token, random_token};
use crate::auth::AuthedUser;
use crate::AppState;

#[derive(Deserialize, Default)]
pub struct CreateHostBody {
    #[serde(default)]
    pub hostname: Option<String>,
}

#[derive(Serialize)]
pub struct CreateHostResponse {
    pub host_id: String,
    pub bootstrap_token: String,
    pub install_command: String,
    pub expires_at: i64,
}

#[derive(Serialize)]
pub struct TierLimitError {
    pub error: &'static str,
    pub limit: u32,
    pub current: i64,
    pub tier: String,
}

/// The body is optional so that provisioning from a script is a one-liner:
/// `curl -X POST -H "Authorization: Bearer nsk_…" https://…/api/hosts`. Requiring a JSON
/// body would mean every caller sending `-H 'Content-Type: application/json' -d '{}'` to
/// supply nothing.
pub async fn create(
    State(state): State<AppState>,
    who: AuthedUser,
    _body: Option<Json<CreateHostBody>>,
) -> Response {
    if !who.role.can_add_hosts() {
        return crate::auth::forbidden("add hosts");
    }
    let tenants_repo = TenantRepo::new(&state.db);
    let hosts_repo = HostRepo::new(&state.db);

    let tenant = match tenants_repo.get(who.tenant_id).await {
        Ok(Some(t)) => t,
        _ => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "tenant missing").into_response();
        }
    };

    let limits = tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());
    let active = match hosts_repo.count_active(tenant.id).await {
        Ok(n) => n,
        Err(e) => {
            tracing::error!(error = %e, "count_active failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "count failed").into_response();
        }
    };
    if (active as u64) >= limits.max_hosts as u64 {
        return (
            StatusCode::FORBIDDEN,
            Json(TierLimitError {
                error: "tier_limit",
                limit: limits.max_hosts,
                current: active,
                tier: limits.name.to_string(),
            }),
        )
            .into_response();
    }

    // Generate bootstrap nonce. We persist its hash on the host row (so the JWT itself
    // contains the unhashed nonce, but a DB leak doesn't reveal valid nonces).
    let nonce = random_token();
    let nonce_hash = hash_token(&nonce);
    let expires_at = now_unix() + state.config.bootstrap_ttl_secs;

    let host = match hosts_repo
        .create_pending(tenant.id, &nonce_hash, expires_at)
        .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "host create_pending failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = BootstrapClaims {
        host_id: host.id.clone(),
        tenant_id: tenant.id,
        nonce,
        iat: now,
        exp: now + state.config.bootstrap_ttl_secs as usize,
    };
    let token = encode_bootstrap(&state.config.bootstrap_jwt_secret, &claims);

    let install_command = format!(
        "nscp enroll --server {} --token {}",
        state.config.base_url.trim_end_matches('/'),
        token
    );

    crate::audit::record(
        &state,
        tenant.id,
        Some(who.user_id),
        "host.created",
        "host",
        &host.id,
        None,
    )
    .await;

    Json(CreateHostResponse {
        host_id: host.id,
        bootstrap_token: token,
        install_command,
        expires_at,
    })
    .into_response()
}

#[derive(Serialize)]
pub struct HostView {
    pub id: String,
    pub hostname: Option<String>,
    pub os: Option<String>,
    pub enrolled_at: Option<i64>,
    pub last_seen_at: Option<i64>,
    pub current_state_hash: Option<String>,
    /// Derived, not stored — see [`fleet_core::host::HostStatus`]. Computed here so the list
    /// and the detail page can never disagree about what a row means.
    pub status: fleet_core::host::HostStatus,
    /// Only set while a bootstrap token is outstanding; lets the UI say how long is left to
    /// run the install command.
    pub bootstrap_expires_at: Option<i64>,
    pub created_at: i64,
}

fn host_view(h: fleet_core::host::Host) -> HostView {
    let status = h.status(now_unix());
    HostView {
        id: h.id,
        hostname: h.hostname,
        os: h.os,
        enrolled_at: h.enrolled_at,
        last_seen_at: h.last_seen_at,
        current_state_hash: h.current_state_hash,
        status,
        bootstrap_expires_at: h.bootstrap_expires_at,
        created_at: h.created_at,
    }
}

pub async fn list(State(state): State<AppState>, who: AuthedUser) -> Response {
    match HostRepo::new(&state.db).list(who.tenant_id).await {
        Ok(hosts) => Json(hosts.into_iter().map(host_view).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Serialize)]
pub struct TagView {
    pub key: String,
    pub value: String,
    pub source: String,
}

#[derive(Serialize)]
pub struct OverrideMeta {
    pub priority: i64,
}

#[derive(Serialize)]
pub struct HostDetail {
    #[serde(flatten)]
    pub host: HostView,
    pub tags: Vec<TagView>,
    /// Present iff a host override exists. The patch itself is never returned (it can
    /// contain secrets); only its priority.
    pub override_meta: Option<OverrideMeta>,
}

pub async fn detail(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
) -> Response {
    let host = match HostRepo::new(&state.db).get(who.tenant_id, &host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let tags = match HostTagsRepo::new(&state.db)
        .list_for_host(who.tenant_id, &host_id)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "tags list failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let override_meta = match HostOverridesRepo::new(&state.db)
        .get(who.tenant_id, &host_id)
        .await
    {
        Ok(o) => o.map(|o| OverrideMeta {
            priority: o.priority,
        }),
        Err(e) => {
            tracing::error!(error = %e, "override get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    Json(HostDetail {
        host: host_view(host),
        tags: tags
            .into_iter()
            .map(|(key, value, source)| TagView { key, value, source })
            .collect(),
        override_meta,
    })
    .into_response()
}

pub async fn delete_host(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let host = match HostRepo::new(&state.db).get(who.tenant_id, &host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    match HostRepo::new(&state.db)
        .delete(who.tenant_id, &host_id)
        .await
    {
        Ok(true) => {
            // config_version covers configuration changes, not a host ceasing to exist.
            state
                .desired_state_cache
                .invalidate_host(who.tenant_id, &host_id);
            crate::audit::record(
                &state,
                who.tenant_id,
                Some(who.user_id),
                "host.deleted",
                "host",
                &host_id,
                Some(&serde_json::json!({
                    "hostname": host.hostname,
                    "enrolled": host.enrolled_at.is_some(),
                })),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host delete failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

#[derive(Serialize)]
pub struct DesiredBundleView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub priority: i64,
}

/// Lineage view for the UI: which bundles the host *should* have, at what priority, and
/// whether the agent's last-reported state matches. The merged config is intentionally
/// omitted — host overrides can contain secrets and this response must stay loggable.
#[derive(Serialize)]
pub struct DesiredStateView {
    pub state_hash: String,
    pub in_sync: bool,
    pub bundles: Vec<DesiredBundleView>,
}

pub async fn desired(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
) -> Response {
    let host = match HostRepo::new(&state.db).get(who.tenant_id, &host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let ds =
        match crate::desired_state::compute_desired_state(&state, who.tenant_id, &host_id).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(error = %e, "compute_desired_state failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        };
    Json(DesiredStateView {
        in_sync: host.current_state_hash.as_deref() == Some(ds.state_hash.as_str()),
        state_hash: ds.state_hash,
        bundles: ds
            .bundles
            .into_iter()
            .map(|b| DesiredBundleView {
                id: b.id,
                name: b.name,
                version: b.version,
                sha256: b.sha256,
                priority: b.priority,
            })
            .collect(),
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct EnrollBody {
    pub bootstrap_token: String,
    pub csr_pem: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
}

#[derive(Serialize)]
pub struct EnrollResponse {
    pub cert_pem: String,
    pub ca_pem: String,
    pub bundle_signing_pub_pem: String,
    pub server_url: String,
    pub mtls_url: String,
    pub mtls_server_cert_pem: String,
}

pub async fn enroll(State(state): State<AppState>, Json(body): Json<EnrollBody>) -> Response {
    use fleet_storage::{HostCertRepo, TenantSecretsRepo};

    let claims = match fleet_enrollment::decode_bootstrap(
        &state.config.bootstrap_jwt_secret,
        &body.bootstrap_token,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "enroll: bad bootstrap token");
            return (StatusCode::UNAUTHORIZED, "invalid bootstrap token").into_response();
        }
    };

    // Per-tenant rate limit. Runs AFTER JWT validation so attackers hammering with bogus
    // tokens don't consume the legitimate tenant's budget.
    if let Err(retry) = state.enrollment_limits.check(claims.tenant_id) {
        let mut resp = (
            StatusCode::TOO_MANY_REQUESTS,
            "enrollment rate limit exceeded",
        )
            .into_response();
        if let Ok(v) = axum::http::HeaderValue::from_str(&retry.to_string()) {
            resp.headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
        return resp;
    }

    let nonce_hash = hash_token(&claims.nonce);
    let hosts_repo = HostRepo::new(&state.db);
    let secrets_repo = TenantSecretsRepo::new(&state.db);
    let tenants_repo = TenantRepo::new(&state.db);

    let tenant = match tenants_repo.get(claims.tenant_id).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::UNAUTHORIZED, "tenant missing").into_response(),
    };

    let secrets = match secrets_repo.get_by_tenant(claims.tenant_id).await {
        Ok(Some(s)) => s,
        _ => {
            tracing::error!(tenant_id = claims.tenant_id, "tenant secrets missing");
            return (StatusCode::INTERNAL_SERVER_ERROR, "tenant secrets missing").into_response();
        }
    };

    let ca_key_pem = match state.config.master_key.decrypt(&secrets.ca_key_encrypted) {
        Ok(b) => match String::from_utf8(b) {
            Ok(s) => s,
            Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "ca key corrupt").into_response(),
        },
        Err(e) => {
            tracing::error!(error = %e, "ca key decrypt failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "ca key decrypt failed").into_response();
        }
    };

    let issued = match fleet_enrollment::sign_client_cert(
        &body.csr_pem,
        &secrets.ca_cert_pem,
        &ca_key_pem,
        &tenant.slug,
        &claims.host_id,
        state.config.client_cert_lifetime_days,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, host_id = %claims.host_id, "enroll: sign failed");
            return (StatusCode::BAD_REQUEST, format!("sign failed: {e}")).into_response();
        }
    };

    let became_enrolled = match hosts_repo
        .mark_enrolled_if_pending(
            claims.tenant_id,
            &claims.host_id,
            &nonce_hash,
            body.hostname.as_deref(),
            body.os.as_deref(),
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "mark_enrolled_if_pending failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if !became_enrolled {
        return (
            StatusCode::UNAUTHORIZED,
            "bootstrap nonce already used or expired",
        )
            .into_response();
    }

    let cert_repo = HostCertRepo::new(&state.db);
    if let Err(e) = cert_repo
        .record(
            claims.tenant_id,
            &claims.host_id,
            &issued.serial_hex,
            &issued.fingerprint_sha256_hex,
            issued.not_before_unix,
            issued.not_after_unix,
        )
        .await
    {
        tracing::error!(error = %e, "host_certs.record failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "record failed").into_response();
    }

    // Load this tenant's CA into the mTLS trust store *before* answering. The response
    // below tells the agent to open an mTLS connection immediately; if the issuing CA is
    // not trusted by then, that first connection dies with `UnknownCA`. Awaited rather
    // than spawned for exactly that reason — see `MtlsContext::ensure_tenant_trusted`.
    //
    // A failure here is logged, not returned: the one-time bootstrap nonce has already
    // been burned, so a 500 would strand the host with no way to retry. The agent's own
    // retry loop recovers once the trust store catches up.
    if let Err(e) = state
        .trust_store
        .ensure_tenant_trusted(claims.tenant_id)
        .await
    {
        tracing::error!(
            error = %e,
            tenant_id = claims.tenant_id,
            host_id = %claims.host_id,
            "enrolled a host whose tenant CA is not in the trust store — its first \
             connections will fail with UnknownCA until a rebuild succeeds"
        );
    }

    crate::audit::record(
        &state,
        claims.tenant_id,
        None,
        "host.enrolled",
        "host",
        &claims.host_id,
        Some(&serde_json::json!({
            "serial": issued.serial_hex,
            "fingerprint_sha256": issued.fingerprint_sha256_hex,
            "hostname": body.hostname,
            "os": body.os
        })),
    )
    .await;

    Json(EnrollResponse {
        cert_pem: issued.cert_pem,
        ca_pem: secrets.ca_cert_pem,
        bundle_signing_pub_pem: secrets.bundle_signing_pub_pem,
        server_url: state.config.base_url.clone(),
        mtls_url: state.config.agent_mtls_url.clone(),
        mtls_server_cert_pem: state.mtls_server_cert_pem.as_ref().clone(),
    })
    .into_response()
}
