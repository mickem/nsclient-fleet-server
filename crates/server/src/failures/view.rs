//! What an operator sees and configures: the failures a tenant's hosts reported, and the
//! settings governing whether reports are taken and which model describes them.

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::crypto::aead::Purpose;
use fleet_core::time::now_unix;
use fleet_storage::{
    utc_day, AuditRepo, FailureContextRepo, FailureContextRow, NewFailureSettings,
    TenantFailureSettingsRepo,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::llm::prompt::Description;
use crate::llm::ProviderKind;
use crate::AppState;

/// Rows a list request may ask for.
const MAX_LIST_LIMIT: i64 = 200;
const DEFAULT_LIST_LIMIT: i64 = 50;

/// Longest `min-interval` an operator may advertise: a week. Past that the setting stops
/// being pacing and starts being an obscure way of turning the feature off, which
/// `reports_enabled` already does clearly.
const MAX_MIN_INTERVAL_SECS: i64 = 7 * 86_400;

/// One failure as a list shows it. The report is not included — a list of fifty would mean
/// fifty decrypts, each of a document holding a few hundred metrics, for data no row renders.
#[derive(Serialize)]
pub struct FailureSummaryView {
    pub id: String,
    pub host_id: String,
    pub command: String,
    pub alias: String,
    pub status: i64,
    pub status_word: String,
    pub message: String,
    pub subject: String,
    /// `captured` | `evicted` | `too_large` | `disabled` | `none`.
    pub context_state: String,
    pub metrics_count: i64,
    /// From the newest report's window, not a running total — the agent groups its summary
    /// across every check, so summing it onto one problem would misattribute.
    pub window_suppressed: i64,
    pub window_evicted: i64,
    pub occurrences: i64,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub enrichment_state: String,
    pub enrichment_error: Option<String>,
    pub enrichment_provider: Option<String>,
    pub enrichment_model: Option<String>,
    pub enriched_at: Option<i64>,
    /// Present once a model has described the failure.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
}

/// One failure in full, including the report the agent sent.
#[derive(Serialize)]
pub struct FailureDetailView {
    #[serde(flatten)]
    pub summary: FailureSummaryView,
    /// The report verbatim, as the agent rendered it.
    pub report: serde_json::Value,
    pub payload_bytes: i64,
    pub enrichment_input_tokens: Option<i64>,
    pub enrichment_output_tokens: Option<i64>,
}

/// Decrypt a row's description, if it has one.
///
/// A description that will not decrypt is reported as absent rather than as an error: the
/// failure itself is still worth showing, and the row is re-describable. The log line is
/// what makes the condition visible.
fn description_of(state: &AppState, row: &FailureContextRow) -> Option<Description> {
    let blob = row.enrichment_encrypted.as_ref()?;
    let purpose = Purpose::FailureContext {
        tenant_id: row.tenant_id,
        host_id: &row.host_id,
    };
    match state.config.master_key.decrypt(purpose, blob) {
        Ok(plain) => match serde_json::from_slice(&plain) {
            Ok(d) => Some(d),
            Err(e) => {
                tracing::error!(failure_id = %row.id, error = %e, "a stored description would not parse");
                None
            }
        },
        Err(e) => {
            tracing::error!(failure_id = %row.id, error = %e, "a stored description would not decrypt");
            None
        }
    }
}

fn summary_view(state: &AppState, row: &FailureContextRow) -> FailureSummaryView {
    FailureSummaryView {
        id: row.id.clone(),
        host_id: row.host_id.clone(),
        command: row.command.clone(),
        alias: row.alias.clone(),
        status: row.status,
        status_word: row.status_word.clone(),
        message: row.message.clone(),
        subject: row.subject.clone(),
        context_state: row.context_state.clone(),
        metrics_count: row.metrics_count,
        window_suppressed: row.window_suppressed,
        window_evicted: row.window_evicted,
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
    /// Nagios status number: 1 warning, 2 critical, 3 unknown.
    #[serde(default)]
    pub status: Option<i64>,
    #[serde(default)]
    pub limit: Option<i64>,
}

/// `GET /api/failures`
pub async fn list(
    State(state): State<AppState>,
    who: AuthedUser,
    Query(q): Query<ListQuery>,
) -> Response {
    // An out-of-range status would otherwise be passed to the query, match nothing, and read
    // to the user as "there are no failures".
    if let Some(s) = q.status {
        if !(0..=3).contains(&s) {
            return (
                StatusCode::BAD_REQUEST,
                "status must be 0 (ok), 1 (warning), 2 (critical) or 3 (unknown)",
            )
                .into_response();
        }
    }
    let limit = q
        .limit
        .unwrap_or(DEFAULT_LIST_LIMIT)
        .clamp(1, MAX_LIST_LIMIT);

    match FailureContextRepo::new(&state.db)
        .list(who.tenant_id, q.host_id.as_deref(), q.status, limit)
        .await
    {
        Ok(rows) => {
            let views: Vec<_> = rows.iter().map(|r| summary_view(&state, r)).collect();
            Json(views).into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, "listing failures failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `GET /api/failures/{id}`
pub async fn get(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    let row = match FailureContextRepo::new(&state.db)
        .get(who.tenant_id, &id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "no such failure").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "reading a failure failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let report = match state.config.master_key.decrypt(
        Purpose::FailureContext {
            tenant_id: row.tenant_id,
            host_id: &row.host_id,
        },
        &row.payload_encrypted,
    ) {
        Ok(plain) => serde_json::from_slice(&plain).unwrap_or(serde_json::Value::Null),
        Err(e) => {
            tracing::error!(failure_id = %row.id, error = %e, "a stored report would not decrypt");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the stored report could not be read",
            )
                .into_response();
        }
    };

    Json(FailureDetailView {
        report,
        payload_bytes: row.payload_bytes,
        enrichment_input_tokens: row.enrichment_input_tokens,
        enrichment_output_tokens: row.enrichment_output_tokens,
        summary: summary_view(&state, &row),
    })
    .into_response()
}

/// `POST /api/failures/{id}/describe` — put a failure back in the enrichment queue.
///
/// The escape hatch after a settings fix. Requires config-write rather than read: it spends
/// money.
pub async fn describe(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    match FailureContextRepo::new(&state.db)
        .requeue(who.tenant_id, &id)
        .await
    {
        Ok(true) => Json(serde_json::json!({ "queued": true })).into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such failure").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "re-queueing a failure failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// `DELETE /api/failures/{id}`
pub async fn delete_failure(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }
    match FailureContextRepo::new(&state.db)
        .delete(who.tenant_id, &id)
        .await
    {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (StatusCode::NOT_FOUND, "no such failure").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "deleting a failure failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
        }
    }
}

/// The tenant's settings, as the console sees them.
///
/// There is no field for the API key. It is write-only by construction: `api_key_set` says
/// whether one is stored, and nothing serves it back — not to an admin, not to a platform
/// admin. A credential that can be read out of the console is a credential that leaves in a
/// screenshot.
#[derive(Serialize)]
pub struct SettingsView {
    /// Whether this server advertises `X-Failure-Context` to this tenant's agents. Off means
    /// agents post nothing — the feature's switch, reachable without touching a host.
    pub reports_enabled: bool,
    /// Advertised as `min-interval`. A floor on the agent's own interval, never a ceiling.
    pub min_interval_secs: i64,
    pub enrichment_enabled: bool,
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

/// `GET /api/failures/settings`
pub async fn get_settings(State(state): State<AppState>, who: AuthedUser) -> Response {
    let repo = TenantFailureSettingsRepo::new(&state.db);
    let stored = match repo.get(who.tenant_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "reading failure settings failed");
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
        Some(s) => SettingsView {
            reports_enabled: s.reports_enabled,
            min_interval_secs: s.min_interval_secs,
            enrichment_enabled: s.enrichment_enabled,
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
        // No row: reports are taken, and what enrichment would do is whatever the process
        // was configured with — so an on-prem operator who set the environment sees that it
        // is live rather than an empty form.
        None => {
            let d = crate::llm::server_default();
            SettingsView {
                reports_enabled: true,
                min_interval_secs: 0,
                enrichment_enabled: d.is_some(),
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
    #[serde(default = "default_true")]
    pub reports_enabled: bool,
    #[serde(default)]
    pub min_interval_secs: Option<i64>,
    #[serde(default)]
    pub enrichment_enabled: bool,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub base_url: Option<String>,
    /// Omitted to keep the stored key; an empty string to clear it.
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub daily_call_budget: Option<i64>,
}

fn default_true() -> bool {
    true
}

/// `PUT /api/failures/settings`
pub async fn put_settings(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<UpdateSettings>,
) -> Response {
    if !who.role.can_write_config() {
        return crate::auth::forbidden("change configuration");
    }

    let min_interval = body.min_interval_secs.unwrap_or(0);
    if !(0..=MAX_MIN_INTERVAL_SECS).contains(&min_interval) {
        return (
            StatusCode::BAD_REQUEST,
            format!("min_interval_secs must be between 0 and {MAX_MIN_INTERVAL_SECS}"),
        )
            .into_response();
    }

    let budget = body.daily_call_budget.unwrap_or(200);
    if !(0..=100_000).contains(&budget) {
        return (
            StatusCode::BAD_REQUEST,
            "daily_call_budget must be between 0 and 100000",
        )
            .into_response();
    }

    let base_url = body
        .base_url
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty());
    let model = body.model.trim();

    // Everything below only has to hold when enrichment is on: a tenant switching it off
    // should not have to supply a valid provider to do so.
    let mut provider = None;
    if body.enrichment_enabled {
        let Some(p) = ProviderKind::parse(&body.provider) else {
            return (
                StatusCode::BAD_REQUEST,
                "provider must be one of anthropic, openai, ollama",
            )
                .into_response();
        };
        if model.is_empty() || model.len() > 128 {
            return (StatusCode::BAD_REQUEST, "model is required").into_response();
        }
        if let Some(u) = base_url {
            // Parsed rather than pattern-matched: this string becomes the host of an
            // outbound request, and "looks like a URL" is not the same as "is one".
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
        provider = Some(p);
    }

    let repo = TenantFailureSettingsRepo::new(&state.db);
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

    // Refuse settings that cannot work, rather than accepting them and letting every failure
    // fail one at a time against a provider with no credential.
    if let Some(p) = provider {
        let will_have_key = match (&encrypted, clearing) {
            (Some(_), _) => true,
            (None, true) => false,
            (None, false) => existing
                .as_ref()
                .is_some_and(|e| e.api_key_encrypted.is_some()),
        };
        if p.requires_api_key() && !will_have_key {
            return (
                StatusCode::BAD_REQUEST,
                format!("provider '{}' needs an API key", p.as_str()),
            )
                .into_response();
        }
    }

    if let Err(e) = repo
        .set(
            who.tenant_id,
            NewFailureSettings {
                reports_enabled: body.reports_enabled,
                min_interval_secs: min_interval,
                enrichment_enabled: body.enrichment_enabled,
                provider: provider.map(|p| p.as_str()).unwrap_or_default(),
                model,
                base_url,
                api_key_encrypted: encrypted.as_deref(),
                daily_call_budget: budget,
                updated_by_user: Some(who.user_id),
            },
        )
        .await
    {
        tracing::error!(error = %e, "saving failure settings failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    }
    if clearing {
        if let Err(e) = repo.clear_api_key(who.tenant_id).await {
            tracing::error!(error = %e, "clearing the stored API key failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    }

    // Turning enrichment on is the moment a tenant's operational data starts leaving this
    // server, so it belongs in the audit log with who did it — and the provider and model are
    // part of "where to". Turning reports off is worth recording too: it changes what the
    // fleet collects.
    let _ = AuditRepo::new(&state.db)
        .record(
            who.tenant_id,
            Some(who.user_id),
            if body.enrichment_enabled {
                "failures.enrichment.enabled"
            } else {
                "failures.enrichment.disabled"
            },
            "tenant",
            &who.tenant_id.to_string(),
            Some(&serde_json::json!({
                "reports_enabled": body.reports_enabled,
                "min_interval_secs": min_interval,
                "provider": provider.map(|p| p.as_str()),
                "model": model,
                "base_url": base_url,
                "daily_call_budget": budget,
            })),
        )
        .await;

    // Enabling enrichment picks up everything that arrived while it was off — those are
    // precisely the failures the operator now wants described.
    let requeued = if body.enrichment_enabled {
        FailureContextRepo::new(&state.db)
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
    match FailureContextRepo::new(db)
        .delete_older_than(super::ingest::RETENTION_SECS)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "swept failures nobody has reported again"),
        Err(e) => tracing::error!(error = %e, "failure sweep failed"),
    }
    match TenantFailureSettingsRepo::new(db)
        .sweep_usage(utc_day(now_unix()), 90)
        .await
    {
        Ok(0) => {}
        Ok(n) => tracing::info!(removed = n, "swept old model-usage rows"),
        Err(e) => tracing::error!(error = %e, "model-usage sweep failed"),
    }
}
