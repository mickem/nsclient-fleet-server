use std::time::{SystemTime, UNIX_EPOCH};

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, State},
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
    /// The address the agent enrolls against — `BASE_URL` — separately from the command,
    /// for tooling that builds its own. The web console does: the bundle encryption key
    /// it appends never reaches this server, so no command built here could carry it.
    pub server_url: String,
    /// `nscp enroll …` without the bundle key, for API users and scripts.
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
        // Stamped by `encode_bootstrap`; the value here is ignored.
        aud: String::new(),
    };
    let token = encode_bootstrap(&state.config.bootstrap_jwt_secret, &claims);

    let server_url = state.config.base_url.trim_end_matches('/').to_string();
    let install_command = format!("nscp enroll --server {server_url} --token {token}");

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
        server_url,
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
    /// and the detail page can never disagree about what a row means, and so that "is this
    /// host doing what we told it" is answered without opening the row.
    pub status: fleet_core::host::HostStatus,
    /// Only set while a bootstrap token is outstanding; lets the UI say how long is left to
    /// run the install command.
    pub bootstrap_expires_at: Option<i64>,
    /// The agent's last answer to whether the host has local configuration outranking the
    /// fleet's. `null` means it has never said — which the UI must not render as "no", since
    /// the honest answer there is that we do not know.
    pub local_config_present: Option<bool>,
    pub created_at: i64,
    /// All of the host's tags, manual and agent-reported alike. Carried on the list view —
    /// not just the detail — so the hosts page can filter and bulk-select by tag without a
    /// request per row.
    pub tags: Vec<TagView>,
}

fn host_view(
    h: fleet_core::host::Host,
    now: i64,
    thresholds: fleet_core::host::StatusThresholds,
    desired_state_hash: Option<&str>,
    tags: Vec<TagView>,
) -> HostView {
    let status = h.status(now, thresholds, desired_state_hash);
    HostView {
        id: h.id,
        hostname: h.hostname,
        os: h.os,
        enrolled_at: h.enrolled_at,
        last_seen_at: h.last_seen_at,
        current_state_hash: h.current_state_hash,
        status,
        bootstrap_expires_at: h.bootstrap_expires_at,
        local_config_present: h.local_config_present,
        created_at: h.created_at,
        tags,
    }
}

/// The fleet, each host carrying the one status that says what it is doing.
///
/// Deciding in-sync means knowing what we would serve each host, so this walks the same
/// `compute_desired_state_at` the agents' poll uses — the memoized one. Sharing that path
/// rather than reimplementing the comparison is the point: a second hash computation that
/// drifted from the agent's would leave the UI insisting a converged fleet is out of sync,
/// which is precisely the bug an operator cannot diagnose from the outside.
///
/// Cost is one cache lookup per enrolled host, and a full recompute per host the first time
/// the list is loaded after a configuration change (the same burst the agents' next poll
/// would cause anyway). At the fleet sizes the tiers allow that is worth paying for a status
/// that is exact; if it ever stops being, the answer is to page the list rather than to
/// cache a second, weaker answer here.
pub async fn list(State(state): State<AppState>, who: AuthedUser) -> Response {
    // One tenant read serves both the silence thresholds (from the tier's poll interval) and
    // the cache key every desired-state lookup below is validated against.
    let tenant = match TenantRepo::new(&state.db).get(who.tenant_id).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::INTERNAL_SERVER_ERROR, "tenant missing").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tenant lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let limits = tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());
    let thresholds = fleet_core::host::StatusThresholds::new(
        limits.min_poll_interval_secs,
        state.config.host_lost_after_secs,
    );

    let hosts = match HostRepo::new(&state.db).list(who.tenant_id).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "host list failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let mut tags_by_host: std::collections::HashMap<String, Vec<TagView>> =
        match HostTagsRepo::new(&state.db)
            .list_for_tenant(who.tenant_id)
            .await
        {
            Ok(rows) => {
                let mut m: std::collections::HashMap<String, Vec<TagView>> =
                    std::collections::HashMap::new();
                for (host_id, key, value, source) in rows {
                    m.entry(host_id)
                        .or_default()
                        .push(TagView { key, value, source });
                }
                m
            }
            Err(e) => {
                tracing::error!(error = %e, "tags list failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        };

    let now = now_unix();
    let mut views = Vec::with_capacity(hosts.len());
    for host in hosts {
        // A host that never enrolled has nothing to be in sync with, and computing a desired
        // state for one would be work spent on an answer its status cannot use.
        let desired = if host.enrolled_at.is_some() {
            match crate::desired_state::compute_desired_state_at(
                &state,
                who.tenant_id,
                &host.id,
                tenant.config_version,
            )
            .await
            {
                Ok(ds) => Some(ds.state_hash),
                // Fail the request rather than the row: a list where one host silently shows
                // the wrong status is worse than a list that failed to load.
                Err(e) => {
                    tracing::error!(error = %e, host_id = %host.id, "desired state failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
                }
            }
        } else {
            None
        };
        let tags = tags_by_host.remove(&host.id).unwrap_or_default();
        views.push(host_view(host, now, thresholds, desired.as_deref(), tags));
    }
    Json(views).into_response()
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
    // Same inputs as the list, so the chip in the header cannot contradict the row the
    // operator clicked to get here.
    let (thresholds, desired_hash) = match status_inputs(&state, who.tenant_id, &host).await {
        Ok(v) => v,
        Err(e) => {
            tracing::error!(error = %e, "status inputs failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let tags = tags
        .into_iter()
        .map(|(key, value, source)| TagView { key, value, source })
        .collect();
    Json(HostDetail {
        host: host_view(host, now_unix(), thresholds, desired_hash.as_deref(), tags),
        override_meta,
    })
    .into_response()
}

/// The two things `Host::status` needs beyond the row itself: the tenant's silence
/// thresholds, and what we would serve this host right now. Only worth its own function for
/// the single-host callers — `list` loads the tenant once and loops instead.
async fn status_inputs(
    state: &AppState,
    tenant_id: i64,
    host: &fleet_core::host::Host,
) -> anyhow::Result<(fleet_core::host::StatusThresholds, Option<String>)> {
    let tenant = TenantRepo::new(&state.db)
        .get(tenant_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("tenant {tenant_id} not found"))?;
    let limits = tier::effective(&tenant.tier, tenant.tier_overrides_json.as_deref());
    let thresholds = fleet_core::host::StatusThresholds::new(
        limits.min_poll_interval_secs,
        state.config.host_lost_after_secs,
    );

    let desired = if host.enrolled_at.is_some() {
        Some(
            crate::desired_state::compute_desired_state_at(
                state,
                tenant_id,
                &host.id,
                tenant.config_version,
            )
            .await?
            .state_hash,
        )
    } else {
        None
    };
    Ok((thresholds, desired))
}

#[derive(Serialize)]
pub struct RevokeHostResponse {
    pub host_id: String,
    /// Certificates this call revoked. Zero is normal for a host that never enrolled.
    pub revoked_certs: u64,
    /// A fresh bootstrap token, because revoking without one would strand the host: its
    /// certificates stop working and enrollment refuses an already-enrolled host.
    pub bootstrap_token: String,
    pub install_command: String,
    pub expires_at: i64,
}

/// Revoke every certificate a host holds and return it to pending with a new bootstrap
/// token.
///
/// The lever for "this host's private key is believed stolen". Before this existed the
/// only way to stop a certificate being accepted was to delete the host, which also threw
/// away its tags, group membership, overrides and history — so in practice nobody did it,
/// and `revoked_at` was a column nothing ever wrote. Keeping the host row means the
/// operator re-runs enrollment and everything else about the host is exactly where they
/// left it.
pub async fn revoke_host_certs(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(host_id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let tenant = match TenantRepo::new(&state.db).get(who.tenant_id).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, "tenant missing").into_response(),
    };

    let nonce = random_token();
    let nonce_hash = hash_token(&nonce);
    let expires_at = now_unix() + state.config.bootstrap_ttl_secs;

    let revoked = match HostRepo::new(&state.db)
        .revoke_certs_and_reset_to_pending(who.tenant_id, &host_id, &nonce_hash, expires_at)
        .await
    {
        Ok(Some(n)) => n,
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "host cert revoke failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    // The host is no longer enrolled, so its desired state is no longer anyone's to serve.
    state
        .desired_state_cache
        .invalidate_host(who.tenant_id, &host_id);

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;
    let claims = BootstrapClaims {
        host_id: host_id.clone(),
        tenant_id: tenant.id,
        nonce,
        iat: now,
        exp: now + state.config.bootstrap_ttl_secs as usize,
        // Stamped by `encode_bootstrap`; the value here is ignored.
        aud: String::new(),
    };
    let token = encode_bootstrap(&state.config.bootstrap_jwt_secret, &claims);
    let install_command = format!(
        "nscp enroll --server {} --token {}",
        state.config.base_url.trim_end_matches('/'),
        token
    );

    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "host.certs_revoked",
        "host",
        &host_id,
        Some(&serde_json::json!({ "revoked_certs": revoked })),
    )
    .await;

    Json(RevokeHostResponse {
        host_id,
        revoked_certs: revoked,
        bootstrap_token: token,
        install_command,
        expires_at,
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

/// How many hosts one bulk request may touch. High enough that "select all" on any fleet the
/// tiers allow fits in one request; low enough that a runaway client cannot queue unbounded
/// work behind a single POST.
const BULK_MAX_HOSTS: usize = 1000;

#[derive(Deserialize)]
pub struct BulkDeleteBody {
    pub host_ids: Vec<String>,
}

#[derive(Serialize)]
pub struct BulkResult {
    pub updated: usize,
    /// IDs that did not match a host in this tenant. Reported rather than failing the whole
    /// request: the likely cause is a host deleted from another tab since the list loaded,
    /// and the operator's intent for the remaining hosts is not in doubt.
    pub not_found: Vec<String>,
}

/// Checks and side effects intentionally identical to [`delete_host`], once per row: each
/// deletion invalidates its cache entry and writes its own audit record, so the audit trail
/// of a bulk delete reads the same as ten single ones.
pub async fn bulk_delete(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<BulkDeleteBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let host_ids = match validate_bulk_ids(body.host_ids) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };

    let repo = HostRepo::new(&state.db);
    let mut deleted = 0usize;
    let mut not_found = Vec::new();
    for host_id in host_ids {
        let host = match repo.get(who.tenant_id, &host_id).await {
            Ok(Some(h)) => h,
            Ok(None) => {
                not_found.push(host_id);
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "host get failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        };
        match repo.delete(who.tenant_id, &host_id).await {
            Ok(true) => {
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
                deleted += 1;
            }
            Ok(false) => not_found.push(host_id),
            Err(e) => {
                tracing::error!(error = %e, "host delete failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }
    Json(BulkResult {
        updated: deleted,
        not_found,
    })
    .into_response()
}

#[derive(Deserialize)]
pub struct TagSet {
    pub key: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct BulkTagsBody {
    pub host_ids: Vec<String>,
    /// Manual tags to upsert on every host.
    #[serde(default)]
    pub set: Vec<TagSet>,
    /// Manual tag keys to delete from every host. A key a host does not carry is simply not
    /// there afterwards — that is not an error the operator can act on.
    #[serde(default)]
    pub remove: Vec<String>,
}

/// Set and/or remove manual tags on many hosts at once. Same semantics as
/// [`crate::config_api::put_tag`] / `delete_tag` per (host, key), but the tenant's
/// config_version is bumped once at the end — one rollout, not one per host.
pub async fn bulk_tags(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<BulkTagsBody>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    let host_ids = match validate_bulk_ids(body.host_ids) {
        Ok(ids) => ids,
        Err(resp) => return resp,
    };
    if body.set.is_empty() && body.remove.is_empty() {
        return (StatusCode::BAD_REQUEST, "nothing to set or remove").into_response();
    }
    for key in body
        .set
        .iter()
        .map(|t| t.key.as_str())
        .chain(body.remove.iter().map(String::as_str))
    {
        if key.trim().is_empty() || key.len() > 128 {
            return (StatusCode::BAD_REQUEST, "invalid key").into_response();
        }
    }

    let hosts_repo = HostRepo::new(&state.db);
    let tags_repo = HostTagsRepo::new(&state.db);
    let mut updated = 0usize;
    let mut not_found = Vec::new();
    // Which hosts actually changed, so only their memoized state is dropped rather than
    // the whole tenant's.
    let mut touched: Vec<String> = Vec::new();
    for host_id in host_ids {
        match hosts_repo.get(who.tenant_id, &host_id).await {
            Ok(Some(_)) => {}
            Ok(None) => {
                not_found.push(host_id);
                continue;
            }
            Err(e) => {
                tracing::error!(error = %e, "host get failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
        let mut host_changed = false;
        for tag in &body.set {
            match tags_repo
                .upsert_manual_tag(who.tenant_id, &host_id, &tag.key, &tag.value)
                .await
            {
                Ok(c) => host_changed |= c,
                Err(e) => {
                    tracing::error!(error = %e, "tag upsert failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
                }
            }
        }
        for key in &body.remove {
            match tags_repo
                .delete_manual_tag(who.tenant_id, &host_id, key)
                .await
            {
                Ok(c) => host_changed |= c,
                Err(e) => {
                    tracing::error!(error = %e, "tag delete failed");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
                }
            }
        }
        if host_changed {
            touched.push(host_id.clone());
        }
        updated += 1;
    }
    for host_id in &touched {
        state
            .desired_state_cache
            .invalidate_host(who.tenant_id, host_id);
    }
    if !touched.is_empty() {
        crate::audit::record(
            &state,
            who.tenant_id,
            Some(who.user_id),
            "host.tags_bulk_changed",
            "host",
            &touched.join(","),
            Some(&serde_json::json!({
                "set": body.set.iter().map(|t| &t.key).collect::<Vec<_>>(),
                "remove": &body.remove,
                "hosts": touched.len(),
            })),
        )
        .await;
    }
    Json(BulkResult { updated, not_found }).into_response()
}

/// Shared body validation for the bulk endpoints: deduplicated (an id sent twice must not
/// delete-then-report-missing), non-empty, and capped at [`BULK_MAX_HOSTS`].
// A Response Err is large, but this is called once per request — not worth a Box.
#[allow(clippy::result_large_err)]
fn validate_bulk_ids(host_ids: Vec<String>) -> Result<Vec<String>, Response> {
    let mut seen = std::collections::HashSet::new();
    let ids: Vec<String> = host_ids
        .into_iter()
        .filter(|id| seen.insert(id.clone()))
        .collect();
    if ids.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "host_ids is empty").into_response());
    }
    if ids.len() > BULK_MAX_HOSTS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("too many hosts (max {BULK_MAX_HOSTS})"),
        )
            .into_response());
    }
    Ok(ids)
}

#[derive(Serialize)]
pub struct DesiredBundleView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub priority: i64,
    pub format: String,
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
                format: b.format,
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

pub async fn enroll(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<EnrollBody>,
) -> Response {
    use fleet_storage::TenantSecretsRepo;

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

    // And a coarse per-source limit alongside it. The per-tenant one bounds the damage to
    // one tenant, which is the right shape for a leaked token — but it is keyed on a value
    // the caller supplies, so a caller holding tokens for several tenants has several
    // budgets. This one they cannot pick.
    if let Err(retry) = state.enrollment_limits.check_source(addr.ip()) {
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

    // Cheap read before the CA-key decrypt and the ECDSA signature below. A replayed but
    // unexpired token used to pay for both before the nonce burn refused it. Not the
    // authority — the burn is, and it re-checks all of this in the statement that clears
    // it — so nothing here can let an enrollment through that the burn would not.
    match hosts_repo
        .bootstrap_pending(claims.tenant_id, &claims.host_id, &nonce_hash)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::info!(host_id = %claims.host_id, "enroll: nonce already used or expired");
            return (
                StatusCode::UNAUTHORIZED,
                "bootstrap nonce already used or expired",
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(error = %e, "bootstrap_pending failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    }

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

    let ca_key_pem = match state.config.master_key.decrypt(
        fleet_core::aead::Purpose::TenantCaKey {
            tenant_id: claims.tenant_id,
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

    // Burn and record together. They used to be two statements, so a failure to record the
    // certificate after the burn left the host marked enrolled with no certificate and its
    // one-time token spent — unrecoverable except by deleting and recreating the host.
    let became_enrolled = match hosts_repo
        .enroll(
            claims.tenant_id,
            &claims.host_id,
            &nonce_hash,
            crate::agent_api::clamp_descriptor(body.hostname.as_deref()).as_deref(),
            crate::agent_api::clamp_descriptor(body.os.as_deref()).as_deref(),
            fleet_storage::EnrolledCert {
                serial: &issued.serial_hex,
                fingerprint_sha256: &issued.fingerprint_sha256_hex,
                issued_at: issued.not_before_unix,
                expires_at: issued.not_after_unix,
            },
        )
        .await
    {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "enroll failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if !became_enrolled {
        // Lost the race with a simultaneous enrollment, or the state changed under us since
        // the pre-check. The signed certificate is discarded rather than recorded.
        return (
            StatusCode::UNAUTHORIZED,
            "bootstrap nonce already used or expired",
        )
            .into_response();
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
