use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::time::now_unix;
use fleet_storage::{HostCertRepo, HostRepo, HostTagsRepo, TenantRepo, TenantSecretsRepo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::mtls::PeerHostContext;
use crate::AppState;

#[derive(Deserialize)]
pub struct DesiredStateQuery {
    #[serde(default)]
    pub current_hash: Option<String>,
}

#[derive(Serialize)]
pub struct BundleRef {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub url: String,
    pub signature: String,
    pub priority: i64,
}

#[derive(Serialize)]
pub struct DesiredStateResponse {
    pub state_hash: String,
    pub next_poll_in_seconds: u32,
    pub merged_config_json: serde_json::Value,
    pub bundles: Vec<BundleRef>,
}

#[derive(Serialize)]
pub struct NotModifiedResponse {
    pub next_poll_in_seconds: u32,
}

pub async fn desired_state(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    Query(q): Query<DesiredStateQuery>,
) -> Response {
    // One tenant read serves both the tier (poll cadence) and the cache key, so a poll that
    // hits the cache costs exactly this query — not the tags/groups/assignments/override
    // walk plus an AEAD decrypt.
    let tenant = TenantRepo::new(&state.db).get(ctx.tenant_id).await;
    let (tier, config_version) = match tenant {
        Ok(Some(t)) => (
            fleet_core::tier::effective(&t.tier, t.tier_overrides_json.as_deref()),
            Some(t.config_version),
        ),
        _ => (fleet_core::tier::FREE, None),
    };
    let next_poll = tier.min_poll_interval_secs;

    // No tenant row means no trustworthy cache key; fall back to computing directly rather
    // than caching against a version we invented.
    let computed = match config_version {
        Some(v) => {
            crate::desired_state::compute_desired_state_at(&state, ctx.tenant_id, &ctx.host_id, v)
                .await
        }
        None => crate::desired_state::compute_uncached(&state, ctx.tenant_id, &ctx.host_id).await,
    };
    let ds = match computed {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "compute_desired_state failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    if q.current_hash.as_deref() == Some(ds.state_hash.as_str()) {
        return (
            StatusCode::NOT_MODIFIED,
            Json(NotModifiedResponse {
                next_poll_in_seconds: next_poll,
            }),
        )
            .into_response();
    }

    let bundles = ds
        .bundles
        .into_iter()
        .map(|b| BundleRef {
            id: b.id.clone(),
            name: b.name,
            version: b.version,
            sha256: b.sha256,
            signature: b.signature,
            priority: b.priority,
            url: format!("/agent/v1/bundles/{}", b.id),
        })
        .collect();

    Json(DesiredStateResponse {
        state_hash: ds.state_hash,
        next_poll_in_seconds: next_poll,
        merged_config_json: ds.merged_config,
        bundles,
    })
    .into_response()
}

#[derive(Deserialize, Default)]
pub struct StateReport {
    #[serde(default)]
    pub applied_state_hash: Option<String>,
    #[serde(default)]
    pub bundles_installed: Vec<serde_json::Value>,
    #[serde(default)]
    pub errors: Vec<String>,
    #[serde(default)]
    pub reported_tags: BTreeMap<String, String>,
    /// Whether the host carries configuration of its own that outranks what we send it.
    ///
    /// `None` means the agent said nothing — a build older than the field — and is stored as
    /// "unknown" rather than folded into `false`. Current agents send it on every report,
    /// both ways round, precisely so the two can be told apart. Only the fact arrives here;
    /// the local configuration itself never leaves the host.
    #[serde(default)]
    pub local_config_present: Option<bool>,
}

pub async fn state_report(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    Json(body): Json<StateReport>,
) -> Response {
    let hosts_repo = HostRepo::new(&state.db);
    let tags_repo = HostTagsRepo::new(&state.db);
    let tenants_repo = TenantRepo::new(&state.db);

    if let Some(hash) = &body.applied_state_hash {
        if let Err(e) = hosts_repo
            .update_current_state_hash(ctx.tenant_id, &ctx.host_id, hash)
            .await
        {
            tracing::error!(error = %e, "update_current_state_hash failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    } else {
        // No applied state — at least update last_seen
        let _ = hosts_repo
            .touch_last_seen(ctx.tenant_id, &ctx.host_id)
            .await;
    }

    // Independent of the applied hash: a host can be perfectly in sync and still have local
    // configuration shadowing what it just applied, which is exactly the case worth showing.
    if let Some(present) = body.local_config_present {
        match hosts_repo
            .set_local_config_present(ctx.tenant_id, &ctx.host_id, present)
            .await
        {
            // Logged on transition only — the flag is reported on every state report, and an
            // unchanged answer is not news. No config_version bump: this describes the host,
            // it does not feed selectors or change what we send.
            Ok(true) => tracing::info!(
                host_id = %ctx.host_id,
                local_config_present = present,
                "host local-configuration status changed"
            ),
            Ok(false) => { /* unchanged */ }
            Err(e) => {
                // Non-fatal: the rest of the report is still worth keeping, and the agent
                // re-sends this on its next pass anyway.
                tracing::error!(error = %e, "set_local_config_present failed");
            }
        }
    }

    if !body.reported_tags.is_empty() {
        match tags_repo
            .upsert_agent_tags(ctx.tenant_id, &ctx.host_id, &body.reported_tags)
            .await
        {
            Ok(true) => {
                if let Err(e) = tenants_repo.bump_config_version(ctx.tenant_id).await {
                    tracing::error!(error = %e, "config_version bump failed");
                }
                // No trust-store rebuild here: it is built purely from tenant CAs
                // (`build_state` reads `list_all_cas` and nothing else), and reported tags
                // cannot change it. Rebuilding re-read every CA and rebuilt a rustls
                // ServerConfig on ordinary agent traffic — one full rebuild per host whose
                // tags shifted.
            }
            Ok(false) => { /* no-op: nothing changed */ }
            Err(e) => {
                tracing::error!(error = %e, "upsert_agent_tags failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }

    if !body.errors.is_empty() {
        tracing::warn!(host_id = %ctx.host_id, errors = ?body.errors, "host reported errors");
    }

    Json(serde_json::json!({})).into_response()
}

#[derive(Deserialize)]
pub struct RenewBody {
    pub csr_pem: String,
}

#[derive(Serialize)]
pub struct RenewResponse {
    pub cert_pem: String,
    pub ca_pem: String,
    pub mtls_server_cert_pem: String,
    pub bundle_signing_pub_pem: String,
}

pub async fn renew(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    Json(body): Json<RenewBody>,
) -> Response {
    // The current cert IS the auth — no bootstrap token. The mTLS layer already validated
    // the chain and resolved (tenant_id, host_id) from it. We re-issue with the same identity.
    let secrets_repo = TenantSecretsRepo::new(&state.db);
    let secrets = match secrets_repo.get_by_tenant(ctx.tenant_id).await {
        Ok(Some(s)) => s,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "tenant secrets missing").into_response(),
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
        &ctx.tenant_slug,
        &ctx.host_id,
        state.config.client_cert_lifetime_days,
    ) {
        Ok(c) => c,
        Err(e) => {
            tracing::info!(error = %e, "renew: sign failed");
            return (StatusCode::BAD_REQUEST, format!("sign failed: {e}")).into_response();
        }
    };

    let cert_repo = HostCertRepo::new(&state.db);
    if let Err(e) = cert_repo
        .record(
            ctx.tenant_id,
            &ctx.host_id,
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

    Json(RenewResponse {
        cert_pem: issued.cert_pem,
        ca_pem: secrets.ca_cert_pem,
        mtls_server_cert_pem: state.mtls_server_cert_pem.as_ref().clone(),
        bundle_signing_pub_pem: secrets.bundle_signing_pub_pem,
    })
    .into_response()
}

// (Helpers used here previously moved into desired_state / bundles modules in Phase 5.)
#[allow(dead_code)]
fn _unused() -> i64 {
    now_unix()
}
