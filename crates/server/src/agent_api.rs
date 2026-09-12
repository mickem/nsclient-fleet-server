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

/// How stale a host's `last_seen_at` may get before a poll rewrites it.
///
/// Every poll from every host passes through the desired-state handler, so refreshing on
/// each one would mean a row update per host per poll interval — a fleet of 5 000 polling
/// every 15 seconds would put a few hundred writes a second on the write connection, for a
/// field whose only consumer is a threshold measured in days. Refreshing at most every five
/// minutes keeps "last seen" accurate to the minute in the UI while dropping the great
/// majority of those writes, and still leaves the offline grace
/// ([`fleet_core::host::DEFAULT_OFFLINE_AFTER_SECS`], 24 hours) nearly three orders of
/// magnitude of headroom.
const LAST_SEEN_REFRESH_SECS: i64 = 300;

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
    /// `plain` or `enc-v1`. Advisory only — agents must trust the NSEB1 magic in the
    /// downloaded bytes over this field (a lying server gains nothing either way, but the
    /// magic is what is covered by the AEAD).
    pub format: String,
}

#[derive(Serialize)]
pub struct DesiredStateResponse {
    /// The tenant these bundles belong to. Part of the descriptor a bundle's signature
    /// covers, and the agent cannot derive it from its certificate (which carries the
    /// slug), so it is sent rather than guessed at. Cross-checked by the signature itself:
    /// the verifying key is per tenant, so a wrong value here just fails verification.
    pub tenant_id: i64,
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

    // The poll itself is contact, and for a host in steady state it is the *only* contact:
    // it polls, gets a 304, and has nothing to report until the configuration changes. Were
    // this not recorded, `last_seen_at` would sit at whenever the host last applied
    // something and the whole fleet would read `offline` while polling exactly on schedule.
    if let Err(e) = HostRepo::new(&state.db)
        .touch_last_seen_if_stale(ctx.tenant_id, &ctx.host_id, LAST_SEEN_REFRESH_SECS)
        .await
    {
        // Liveness is not worth failing a poll over: the agent still needs its answer.
        tracing::error!(error = %e, "touch_last_seen_if_stale failed");
    }

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
            format: b.format,
        })
        .collect();

    Json(DesiredStateResponse {
        tenant_id: ctx.tenant_id,
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
    /// The host's full view of its own tags, or `None` when the field is absent and the
    /// agent is saying nothing. An explicit `{}` is an answer — it clears them.
    #[serde(default)]
    pub reported_tags: Option<BTreeMap<String, String>>,
    /// Whether the host carries configuration of its own that outranks what we send it.
    ///
    /// `None` means the agent said nothing — a build older than the field — and is stored as
    /// "unknown" rather than folded into `false`. Current agents send it on every report,
    /// both ways round, precisely so the two can be told apart. Only the fact arrives here;
    /// the local configuration itself never leaves the host.
    #[serde(default)]
    pub local_config_present: Option<bool>,
}

/// Longest hostname or OS string we will store. Both are the host's own description of
/// itself and both are rendered in the console.
pub const MAX_HOST_DESCRIPTOR_LEN: usize = 256;

/// Most error strings one report may carry, and how long each may be. An agent reporting
/// its bundle failures needs a handful of lines, not a log file.
const MAX_ERRORS: usize = 32;
const MAX_ERROR_LEN: usize = 512;

/// A state hash is a SHA-256 in hex, and nothing else is meaningful.
///
/// It was stored verbatim up to the body limit and echoed back into the console, so a host
/// could put two megabytes of anything into a field an operator reads.
fn valid_state_hash(h: &str) -> bool {
    h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Trim what a host says about itself to something storable, or None if it says nothing.
///
/// Truncates rather than refusing: a hostname is descriptive, not load-bearing, and
/// refusing an enrollment over a long one would be a worse outcome than storing 256
/// characters of it.
pub fn clamp_descriptor(v: Option<&str>) -> Option<String> {
    let v = v?.trim();
    if v.is_empty() {
        return None;
    }
    Some(v.chars().take(MAX_HOST_DESCRIPTOR_LEN).collect())
}

/// Bound what a host may store about itself.
///
/// The limits are the selector's own: a key or value longer than a selector can compare is
/// something that could never be matched, so accepting it is storing what cannot be used.
/// Agent tags were previously taken as sent, with no cap on count or length, and were never
/// deleted except with the host.
fn check_reported_tags(tags: &BTreeMap<String, String>) -> Result<(), &'static str> {
    use fleet_core::selector::{MAX_KEY_LEN, MAX_TAGS_PER_HOST, MAX_VALUE_LEN};
    if tags.len() > MAX_TAGS_PER_HOST {
        return Err("too many tags");
    }
    for (k, v) in tags {
        if k.trim().is_empty() || k.len() > MAX_KEY_LEN {
            return Err("tag key is empty or too long");
        }
        if v.len() > MAX_VALUE_LEN {
            return Err("tag value is too long");
        }
    }
    Ok(())
}

pub async fn state_report(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    Json(body): Json<StateReport>,
) -> Response {
    let hosts_repo = HostRepo::new(&state.db);
    let tags_repo = HostTagsRepo::new(&state.db);

    if let Some(hash) = &body.applied_state_hash {
        if !valid_state_hash(hash) {
            tracing::info!(host_id = %ctx.host_id, "rejected a malformed applied_state_hash");
            return (
                StatusCode::BAD_REQUEST,
                "applied_state_hash must be 64 hex characters",
            )
                .into_response();
        }
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

    if let Some(reported) = &body.reported_tags {
        if let Err(msg) = check_reported_tags(reported) {
            tracing::info!(host_id = %ctx.host_id, %msg, "rejected reported tags");
            return (StatusCode::BAD_REQUEST, msg).into_response();
        }
        match tags_repo
            .replace_agent_tags(ctx.tenant_id, &ctx.host_id, reported)
            .await
        {
            Ok(true) => {
                // This host's entry, not the tenant's config version. A host's own tags
                // change only its own group membership, but bumping the version made every
                // other host's cached state stale too — so one host toggling a value at its
                // allowed request rate kept the whole tenant recomputing, on every poll and
                // on every hosts-page load.
                state
                    .desired_state_cache
                    .invalidate_host(ctx.tenant_id, &ctx.host_id);

                // No trust-store rebuild here: it is built purely from tenant CAs
                // (`build_state` reads `list_all_cas` and nothing else), and reported tags
                // cannot change it. Rebuilding re-read every CA and rebuilt a rustls
                // ServerConfig on ordinary agent traffic — one full rebuild per host whose
                // tags shifted.
            }
            Ok(false) => { /* no-op: nothing changed */ }
            Err(e) => {
                tracing::error!(error = %e, "replace_agent_tags failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }

    if !body.errors.is_empty() {
        // Capped on both axes before it reaches a log line. These are not stored, but they
        // are written to the journal verbatim, and "the host decides how much it writes to
        // your disk" is not a property worth having.
        let shown: Vec<String> = body
            .errors
            .iter()
            .take(MAX_ERRORS)
            .map(|e| e.chars().take(MAX_ERROR_LEN).collect())
            .collect();
        tracing::warn!(
            host_id = %ctx.host_id,
            reported = body.errors.len(),
            errors = ?shown,
            "host reported errors"
        );
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

    let ca_key_pem = match state.config.master_key.decrypt(
        fleet_core::aead::Purpose::TenantCaKey {
            tenant_id: ctx.tenant_id,
        },
        &secrets.ca_key_encrypted,
    ) {
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
