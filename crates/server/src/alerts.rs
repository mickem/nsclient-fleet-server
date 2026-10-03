//! `POST /agent/v1/alert-context` — the ingest — plus the tenant-facing `/api/alerts*`
//! routes that read what it stored and configure how it is described.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::aead::Purpose;
use fleet_core::alert::{new_alert_id, AlertReport, MAX_REPORT_BYTES};
use fleet_core::time::now_unix;
use fleet_storage::{
    utc_day, AlertContextRepo, AlertContextRow, AuditRepo, TenantLlmRepo, UpsertOutcome,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::llm::prompt::Description;
use crate::llm::ProviderKind;
use crate::mtls::PeerHostContext;
use crate::AppState;

/// Distinct problems one host may have on file at once.
///
/// The bound that holds when retention does not. A check whose arguments carry something
/// variable — a timestamp, a PID, a generated filename — produces a fresh fingerprint on
/// every run, and every one of those rows is too new to sweep. Without this, one
/// misconfigured check on one host fills the table.
const MAX_ALERTS_PER_HOST: i64 = 200;

/// How long an alert nobody has seen again is kept.
const RETENTION_SECS: i64 = 30 * 86_400;

/// Rows a list request may ask for.
const MAX_LIST_LIMIT: i64 = 200;
const DEFAULT_LIST_LIMIT: i64 = 50;

/// What the agent gets back, so it can tell whether to keep a local copy.
#[derive(Serialize)]
pub struct AlertIngestResponse {
    pub accepted: usize,
    /// Alerts the server dropped as malformed. Reported rather than silently swallowed so a
    /// misbehaving agent build is visible from the agent's own logs.
    pub rejected: usize,
}

/// `POST /agent/v1/alert-context`, on the mTLS router.
///
/// The host is identified by its client certificate, exactly as the other agent routes are:
/// there is no host id in the body, and an agent therefore cannot file an alert against a
/// host that is not itself.
pub async fn ingest(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    body: axum::body::Bytes,
) -> Response {
    // Checked against the raw bytes, before parsing. The per-field caps inside
    // `AlertReport::normalize` bound a well-formed document; this is what bounds a hostile
    // one, and it costs a length comparison.
    if body.len() > MAX_REPORT_BYTES {
        tracing::info!(
            host_id = %ctx.host_id,
            bytes = body.len(),
            "rejected an oversized alert report"
        );
        return (StatusCode::PAYLOAD_TOO_LARGE, "alert report too large").into_response();
    }

    let mut report: AlertReport = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("malformed alert report: {e}"),
            )
                .into_response()
        }
    };

    let dropped = match report.normalize() {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };
    if !dropped.is_empty() {
        tracing::info!(
            host_id = %ctx.host_id,
            dropped = dropped.len(),
            first = %dropped[0],
            "dropped malformed alerts from a report"
        );
    }

    let repo = AlertContextRepo::new(&state.db);
    let mut accepted = 0usize;
    let mut created = 0usize;

    for alert in &report.alerts {
        let payload = match serde_json::to_vec(alert) {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "could not serialise an alert we just parsed");
                continue;
            }
        };
        let ciphertext = state.config.master_key.encrypt(
            Purpose::AlertContext {
                tenant_id: ctx.tenant_id,
                host_id: &ctx.host_id,
            },
            &payload,
        );

        match repo
            .upsert(
                &new_alert_id(),
                ctx.tenant_id,
                &ctx.host_id,
                &alert.fingerprint(),
                &alert.command,
                alert.alias.as_deref(),
                alert.status.as_str(),
                &alert.summary_line(),
                &ciphertext,
                payload.len() as i64,
            )
            .await
        {
            Ok(UpsertOutcome::Created) => {
                accepted += 1;
                created += 1;
            }
            Ok(UpsertOutcome::Updated) => accepted += 1,
            Err(e) => {
                tracing::error!(error = %e, host_id = %ctx.host_id, "storing an alert failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }

    // Only after a new row was added — a repeat cannot take the host over the cap, and
    // trimming on every report would be a delete query per check per interval.
    if created > 0 {
        match repo.count_for_host(ctx.tenant_id, &ctx.host_id).await {
            Ok(n) if n > MAX_ALERTS_PER_HOST => {
                match repo
                    .trim_host(ctx.tenant_id, &ctx.host_id, MAX_ALERTS_PER_HOST)
                    .await
                {
                    Ok(removed) if removed > 0 => tracing::info!(
                        host_id = %ctx.host_id,
                        removed,
                        "trimmed a host's oldest alerts at the per-host cap"
                    ),
                    Ok(_) => {}
                    Err(e) => tracing::error!(error = %e, "trimming a host's alerts failed"),
                }
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "counting a host's alerts failed"),
        }
    }

    Json(AlertIngestResponse {
        accepted,
        rejected: dropped.len(),
    })
    .into_response()
}

/// One alert as the console reads it. The payload is not included here — a list of fifty
/// would mean fifty decrypts for data nothing on the page renders.
#[derive(Serialize)]
pub struct AlertSummaryView {
    pub id: String,
    pub host_id: String,
    pub command: String,
    pub alias: Option<String>,
    pub status: String,
    pub message: String,
    pub occurrences: i64,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub enrichment_state: String,
    pub enrichment_error: Option<String>,
    pub enrichment_provider: Option<String>,
    pub enrichment_model: Option<String>,
    pub enriched_at: Option<i64>,
    /// Present once a model has described the alert.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// One alert in full, including the evidence.
#[derive(Serialize)]
pub struct AlertDetailView {
    #[serde(flatten)]
    pub summary: AlertSummaryView,
    pub payload: serde_json::Value,
    pub payload_bytes: i64,
    pub enrichment_input_tokens: Option<i64>,
    pub enrichment_output_tokens: Option<i64>,
}

/// Decrypt a row's description, if it has one.
///
/// A description that will not decrypt is reported as absent rather than as an error: the
/// alert itself is still worth showing, and the row is re-describable. The log line is what
/// makes the condition visible.
fn description_of(state: &AppState, row: &AlertContextRow) -> Option<Description> {
    let blob = row.enrichment_encrypted.as_ref()?;
    let purpose = Purpose::AlertContext {
        tenant_id: row.tenant_id,
        host_id: &row.host_id,
    };
    match state.config.master_key.decrypt(purpose, blob) {
        Ok(plain) => match serde_json::from_slice(&plain) {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::error!(alert_id = %row.id, error = %e, "a stored description would not parse");
                None
            }
        },
        Err(e) => {
            tracing::error!(alert_id = %row.id, error = %e, "a stored description would not decrypt");
            None
        }
    }
}

fn summary_view(state: &AppState, row: &AlertContextRow) -> AlertSummaryView {
    AlertSummaryView {
        id: row.id.clone(),
        host_id: row.host_id.clone(),
        command: row.command.clone(),
        alias: row.alias.clone(),
        status: row.status.clone(),
        message: row.message.clone(),
        occurrences: row.occurrences,
        first_seen_at: row.first_seen_at,
        last_seen_at: row.last_seen_at,
        enrichment_state: row.enrichment_state.clone(),
        enrichment_error: row.enrichment_error.clone(),
        enrichment_provider: row.enrichment_provider.clone(),
        enrichment_model: row.enrichment_model.clone(),
        enriched_at: row.enriched_at,
        description: description_of(state, row),
    }
}

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub host_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /api/alerts`
pub async fn list(
    State(state): State<AppState>,
    who: AuthedUser,
    Query(q): Query<ListQuery>,
) -> Response {
    // An unrecognised status would otherwise be passed to the query and silently match
    // nothing, which reads to the user as "there are no alerts".
    if let Some(s) = q.status.as_deref() {
        if fleet_core::alert::AlertStatus::parse(s).is_none() {
            return (
                StatusCode::BAD_REQUEST,
                "status must be warning or critical",
            )
                .into_response();
        }
    }
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    match AlertContextRepo::new(&state.db)
        .list(
            who.tenant_id,
            q.host_id.as_deref(),
            q.status.as_deref(),
            limit,
        )
        .await
    {
        Ok(rows) => {
            let views: Vec<_> = rows.iter().map(|r| summary_view(&state, r)).collect();
            Json(views).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "listing alerts failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `GET /api/alerts/:id`
pub async fn get(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    let row = match AlertContextRepo::new(&state.db)
        .get(who.tenant_id, &id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such alert").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "reading an alert failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let payload = match state.config.master_key.decrypt(
        Purpose::AlertContext {
            tenant_id: row.tenant_id,
            host_id: &row.host_id,
        },
        &row.payload_encrypted,
    ) {
        Ok(plain) => serde_json::from_slice(&plain).unwrap_or(serde_json::Value::Null),
        Err(e) => {
            tracing::error!(alert_id = %row.id, error = %e, "a stored alert would not decrypt");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the stored evidence could not be read",
            )
                .into_response();
        }
    };

    Json(AlertDetailView {
        payload,
        payload_bytes: row.payload_bytes,
        enrichment_input_tokens: row.enrichment_input_tokens,
        enrichment_output_tokens: row.enrichment_output_tokens,
        summary: summary_view(&state, &row),
    })
    .into_response()
}

/// `POST /api/alerts/:id/describe` — put an alert back in the enrichment queue.
///
/// The escape hatch after a configuration fix. Requires config-write rather than read: it
/// spends money.
pub async fn describe(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    match AlertContextRepo::new(&state.db)
        .requeue(who.tenant_id, &id)
        .await
    {
        Ok(true) => Json(serde_json::json!({ "queued": true })).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such alert").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "re-queueing an alert failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `DELETE /api/alerts/:id`
pub async fn delete_alert(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    match AlertContextRepo::new(&state.db)
        .delete(who.tenant_id, &id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such alert").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "deleting an alert failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// The tenant's model configuration, as the console sees it.
///
/// There is no field for the API key. It is write-only by construction: `api_key_set` says
/// whether one is stored, and nothing serves it back — not to the browser, not to an admin,
/// not to a platform admin. A credential that can be read out of the console is a credential
/// that leaves in a screenshot.
#[derive(Serialize)]
pub struct LlmSettingsView {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    pub base_url: Option<String>,
    pub api_key_set: bool,
    pub daily_call_budget: i64,
    /// True when this tenant has no row and the process-wide default applies.
    pub inherits_server_default: bool,
    pub calls_today: i64,
    pub failures_today: i64,
    pub updated_at: Option<i64>,
    /// What this server can be configured to talk to.
    pub available_providers: Vec<&'static str>,
}

/// `GET /api/alerts/settings`
pub async fn get_settings(State(state): State<AppState>, who: AuthedUser) -> Response {
    let repo = TenantLlmRepo::new(&state.db);
    let stored = match repo.get(who.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "reading enrichment settings failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let usage = repo
        .usage(who.tenant_id, utc_day(now_unix()))
        .await
        .unwrap_or_default();

    let available_providers = vec![
        ProviderKind::Anthropic.as_str(),
        ProviderKind::OpenAi.as_str(),
        ProviderKind::Ollama.as_str(),
    ];

    let view = match stored {
        Some(s) => LlmSettingsView {
            enabled: s.enabled,
            provider: s.provider,
            model: s.model,
            base_url: s.base_url,
            api_key_set: s.api_key_encrypted.is_some(),
            daily_call_budget: s.daily_call_budget,
            inherits_server_default: false,
            calls_today: usage.calls,
            failures_today: usage.failures,
            updated_at: Some(s.updated_at),
            available_providers,
        },
        // No row: report what the process-wide default would do, so an on-prem operator who
        // configured the environment sees that it is live rather than an empty form.
        None => {
            let d = crate::llm::server_default();
            LlmSettingsView {
                enabled: d.is_some(),
                provider: d
                    .map(|c| c.provider.as_str().to_string())
                    .unwrap_or_default(),
                model: d.map(|c| c.model.clone()).unwrap_or_default(),
                base_url: d.and_then(|c| c.base_url.clone()),
                api_key_set: d.is_some_and(|c| c.api_key.is_some()),
                daily_call_budget: d.map(|c| c.daily_call_budget).unwrap_or(0),
                inherits_server_default: true,
                calls_today: usage.calls,
                failures_today: usage.failures,
                updated_at: None,
                available_providers,
            }
        }
    };
    Json(view).into_response()
}

#[derive(Deserialize)]
pub struct UpdateSettings {
    pub enabled: bool,
    pub provider: String,
    pub model: String,
    #[serde(default)]
    pub base_url: Option<String>,
    /// Omitted to keep the stored key; an empty string to clear it.
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub daily_call_budget: Option<i64>,
}

/// `PUT /api/alerts/settings`
pub async fn put_settings(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<UpdateSettings>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }

    let Some(provider) = ProviderKind::parse(&body.provider) else {
        return (
            StatusCode::BAD_REQUEST,
            "provider must be one of anthropic, openai, ollama",
        )
            .into_response();
    };
    let model = body.model.trim();
    if model.is_empty() || model.len() > 128 {
        return (StatusCode::BAD_REQUEST, "model is required").into_response();
    }
    let base_url = body
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    if let Some(u) = base_url {
        // Parsed rather than pattern-matched: this string becomes the host of an outbound
        // request, and "looks like a URL" is not the same as "is one".
        match url::Url::parse(u) {
            Ok(parsed) if matches!(parsed.scheme(), "http" | "https") => {}
            _ => {
                return (
                    StatusCode::BAD_REQUEST,
                    "base_url must be an http or https URL",
                )
                    .into_response()
            }
        }
    }
    let budget = body.daily_call_budget.unwrap_or(200);
    if !(0..=100_000).contains(&budget) {
        return (
            StatusCode::BAD_REQUEST,
            "daily_call_budget must be between 0 and 100000",
        )
            .into_response();
    }

    let repo = TenantLlmRepo::new(&state.db);
    let existing = repo.get(who.tenant_id).await.ok().flatten();

    // `None` keeps whatever is stored, `Some("")` clears it, anything else replaces it.
    let clearing = body.api_key.as_deref().is_some_and(|k| k.trim().is_empty());
    let encrypted = body
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            state.config.master_key.encrypt(
                Purpose::TenantLlmApiKey {
                    tenant_id: who.tenant_id,
                },
                k.as_bytes(),
            )
        });

    // Refuse a configuration that cannot work, rather than accepting it and letting every
    // alert fail one at a time against a provider with no credential.
    let will_have_key = match (&encrypted, clearing) {
        (Some(_), _) => true,
        (None, true) => false,
        (None, false) => existing
            .as_ref()
            .is_some_and(|e| e.api_key_encrypted.is_some()),
    };
    if body.enabled && provider.requires_api_key() && !will_have_key {
        return (
            StatusCode::BAD_REQUEST,
            format!("provider '{}' needs an API key", provider.as_str()),
        )
            .into_response();
    }

    if let Err(e) = repo
        .set(
            who.tenant_id,
            body.enabled,
            provider.as_str(),
            model,
            base_url,
            encrypted.as_deref(),
            budget,
            Some(who.user_id),
        )
        .await
    {
        tracing::error!(error = %e, "saving enrichment settings failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    }
    if clearing {
        if let Err(e) = repo.clear_api_key(who.tenant_id).await {
            tracing::error!(error = %e, "clearing the stored API key failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    }

    // Turning this on is the moment a tenant's operational data starts leaving this
    // server, so it belongs in the audit log with who did it — and the provider and model
    // are part of "where to".
    let _ = AuditRepo::new(&state.db)
        .record(
            who.tenant_id,
            Some(who.user_id),
            if body.enabled {
                "alerts.enrichment.enabled"
            } else {
                "alerts.enrichment.disabled"
            },
            "tenant",
            &who.tenant_id.to_string(),
            Some(&serde_json::json!({
                "provider": provider.as_str(),
                "model": model,
                "base_url": base_url,
                "daily_call_budget": budget,
            })),
        )
        .await;

    // Enabling it picks up everything that arrived while it was off — those are precisely
    // the alerts the operator now wants described.
    let requeued = if body.enabled {
        AlertContextRepo::new(&state.db)
            .requeue_skipped(who.tenant_id)
            .await
            .unwrap_or(0)
    } else {
        0
    };

    Json(serde_json::json!({ "saved": true, "requeued": requeued })).into_response()
}

/// Retention sweep, called from the housekeeping loop.
pub async fn sweep(db: &fleet_storage::Db) {
    match AlertContextRepo::new(db)
        .delete_older_than(RETENTION_SECS)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "swept alerts nobody has seen again"),
        Err(e) => tracing::error!(error = %e, "alert sweep failed"),
    }
    match TenantLlmRepo::new(db)
        .sweep_usage(utc_day(now_unix()), 90)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "swept old model-usage rows"),
        Err(e) => tracing::error!(error = %e, "model-usage sweep failed"),
    }
}
