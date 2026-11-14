//! `POST /api/explain` — explain an error against a host's latest evidence.
//!
//! The caller holds an error from their monitoring system: pasted into the console, or passed
//! by a script or `check_nsclient`. They name the host it is about, and optionally the check.
//! This gathers what the fleet knows about that host — the agent's latest report of the
//! check, the host's latest metrics snapshot, its inventory facts and tags — and asks the
//! tenant's model to explain the error against it. The answer is returned, not stored: it is
//! an answer to one person's question, and the next person may paste a different error.
//!
//! # What it is careful about
//!
//! **Spend.** A model call is the only thing this server does that costs money per unit, and
//! this route can be driven by an API key in a loop. Every call passes the tenant's daily
//! budget first and counts against it whether or not it succeeded.
//!
//! **Consent.** A tenant that has not turned explanations on gets a refusal that says so, and
//! nothing is sent anywhere. Nothing about a customer's hosts leaves this server until
//! someone has configured where.
//!
//! **Not guessing the host.** Hostnames are not unique. A name that matches two hosts is
//! refused with their ids rather than explained against whichever came first.

use std::sync::OnceLock;

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::crypto::aead::Purpose;
use fleet_core::facts::AGENT_SOURCE;
use fleet_core::failures::FailureReport;
use fleet_core::host::Host;
use fleet_storage::{
    utc_day, FailureContextRepo, FailureContextRow, HostFactsRepo, HostRepo, HostTagsRepo,
    TenantFailureSettingsRepo,
};
use serde::{Deserialize, Serialize};

use crate::auth::AuthedUser;
use crate::llm::prompt::{
    self, ExplainInput, Explanation, FactsDocument, HostContext, StoredReport, MAX_ERROR_CHARS,
};
use crate::llm::{LlmConfig, LlmRequest, ProviderKind};
use crate::AppState;

/// Reports considered when matching an error to a check. The per-host cap is 200; the
/// newest of those are the ones an error in hand is about.
const MATCH_WINDOW: i64 = 200;

/// Shortest alias or command that may be matched by appearing in the error text. A one- or
/// two-letter alias (`c`, `db`) appears inside every other word.
const MIN_MATCH_LEN: usize = 3;

#[derive(Deserialize)]
pub struct ExplainRequest {
    /// The host's id, or its hostname.
    pub host: String,
    /// The error, as the monitoring system reported it.
    pub error: String,
    /// The check the error is about — a command (`check_drivesize`) or an alias (`disk_c`).
    /// Optional: without it, a check named in the error is used if there is one.
    #[serde(default)]
    pub check: Option<String>,
}

/// One stored report, as an explanation cites it.
#[derive(Serialize)]
pub struct EvidenceRef {
    pub id: String,
    pub command: String,
    pub alias: String,
    pub status_word: String,
    pub context_state: String,
    pub metrics_count: i64,
    pub reported_at: i64,
}

impl From<&FailureContextRow> for EvidenceRef {
    fn from(r: &FailureContextRow) -> Self {
        Self {
            id: r.id.clone(),
            command: r.command.clone(),
            alias: r.alias.clone(),
            status_word: r.status_word.clone(),
            context_state: r.context_state.clone(),
            metrics_count: r.metrics_count,
            reported_at: r.reported_at,
        }
    }
}

#[derive(Serialize)]
pub struct ExplainResponse {
    pub host_id: String,
    pub hostname: Option<String>,
    pub explanation: Explanation,
    /// The agent's latest report of the check the error was matched to, if any.
    pub check: Option<EvidenceRef>,
    /// The report whose metrics snapshot was used — the host's latest — if there is one.
    pub snapshot: Option<EvidenceRef>,
    /// The facts sources that were included, the agent's own first.
    pub facts_sources: Vec<String>,
    pub provider: String,
    pub model: String,
    pub input_tokens: Option<i64>,
    pub output_tokens: Option<i64>,
}

/// One client for the life of the process: connection reuse matters against a provider on
/// the other side of a TLS handshake, and the timeout bounds how long a request can hang.
fn http() -> Option<&'static reqwest::Client> {
    static CLIENT: OnceLock<Option<reqwest::Client>> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(crate::llm::CALL_TIMEOUT)
                .build()
                .map_err(|e| tracing::error!(error = %e, "could not build the HTTP client"))
                .ok()
        })
        .as_ref()
}

pub async fn explain(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<ExplainRequest>,
) -> Response {
    let error = body.error.trim();
    if error.is_empty() {
        return (StatusCode::BAD_REQUEST, "error is required").into_response();
    }
    if error.chars().count() > MAX_ERROR_CHARS {
        return (
            StatusCode::BAD_REQUEST,
            format!("error may be at most {MAX_ERROR_CHARS} characters"),
        )
            .into_response();
    }

    let host = match resolve_host(&state, who.tenant_id, body.host.trim()).await {
        Ok(h) => h,
        Err(r) => return r,
    };

    // Settings before evidence: a tenant with explanations off should hear that, not wait
    // for a decrypt it was never going to use.
    let cfg = match resolve_config(&state, who.tenant_id).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return (
                StatusCode::CONFLICT,
                "explanations are not enabled for this tenant; an admin can turn them on under Settings",
            )
                .into_response()
        }
        Err(e) => {
            return (
                StatusCode::CONFLICT,
                format!("explanations are misconfigured for this tenant: {e}"),
            )
                .into_response()
        }
    };

    let usage = TenantFailureSettingsRepo::new(&state.db);
    let today = utc_day(fleet_core::time::now_unix());
    let spent = match usage.usage(who.tenant_id, today).await {
        Ok(u) => u.calls,
        Err(e) => {
            tracing::error!(error = %e, "reading model usage failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if spent >= cfg.daily_call_budget {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            format!(
                "this tenant's daily budget of {} explanations is spent; it resets at midnight UTC",
                cfg.daily_call_budget
            ),
        )
            .into_response();
    }

    let evidence = match gather(&state, who.tenant_id, &host, error, body.check.as_deref()).await {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(error = %e, host_id = %host.id, "gathering evidence failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    let input = ExplainInput {
        error,
        host: &evidence.host,
        check: evidence.check.as_ref().map(|(row, r)| StoredReport {
            report: r,
            reported_at: row.reported_at,
        }),
        snapshot: evidence.snapshot.as_ref().map(|(row, r)| StoredReport {
            report: r,
            reported_at: row.reported_at,
        }),
        facts: &evidence.facts,
    };
    let req = LlmRequest {
        system: prompt::SYSTEM_PROMPT.to_string(),
        user: prompt::build_user_message(&input),
        schema: prompt::answer_schema(),
        max_output_tokens: prompt::MAX_OUTPUT_TOKENS,
    };

    let Some(http) = http() else {
        return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
    };
    let result = cfg.provider_impl().complete(http, &cfg, &req).await;

    // Counted before the result is inspected: the request was made, and a provider that read
    // the prompt before failing has usually billed for it.
    let (in_tok, out_tok) = match &result {
        Ok(r) => (r.input_tokens.unwrap_or(0), r.output_tokens.unwrap_or(0)),
        Err(_) => (0, 0),
    };
    if let Err(e) = usage
        .record_call(who.tenant_id, today, result.is_err(), in_tok, out_tok)
        .await
    {
        tracing::error!(error = %e, "recording a model call failed");
    }

    let explanation = match result.and_then(|r| {
        crate::llm::extract_json(&r.text)
            .and_then(|v| Explanation::from_json(&v))
            .map(|x| (x, r.input_tokens, r.output_tokens))
    }) {
        Ok(x) => x,
        Err(e) => {
            tracing::info!(tenant_id = who.tenant_id, error = %e, "an explanation failed");
            return (StatusCode::BAD_GATEWAY, e.to_string()).into_response();
        }
    };

    tracing::info!(
        tenant_id = who.tenant_id,
        host_id = %host.id,
        provider = cfg.provider.as_str(),
        model = %cfg.model,
        // Deliberately not the error or the explanation: both restate evidence from a
        // customer's host, and the journal is not where that belongs.
        input_tokens = in_tok,
        output_tokens = out_tok,
        "explained an error"
    );

    let (explanation, input_tokens, output_tokens) = explanation;
    Json(ExplainResponse {
        host_id: host.id.clone(),
        hostname: host.hostname.clone(),
        explanation,
        check: evidence.check.as_ref().map(|(row, _)| row.into()),
        snapshot: evidence.snapshot.as_ref().map(|(row, _)| row.into()),
        facts_sources: evidence.facts.iter().map(|f| f.source.clone()).collect(),
        provider: cfg.provider.as_str().to_string(),
        model: cfg.model.clone(),
        input_tokens,
        output_tokens,
    })
    .into_response()
}

/// The host named by `key`: an id first, then a hostname. Answers with the response to send
/// when there is no single host.
// result_large_err: the Err is a ready-to-send Response by design, as in bundles/.
#[allow(clippy::result_large_err)]
async fn resolve_host(state: &AppState, tenant_id: i64, key: &str) -> Result<Host, Response> {
    if key.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "host is required").into_response());
    }
    let repo = HostRepo::new(&state.db);
    let internal = |e: anyhow::Error| {
        tracing::error!(error = %e, "host lookup failed");
        (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response()
    };
    if let Some(h) = repo.get(tenant_id, key).await.map_err(internal)? {
        return Ok(h);
    }
    let mut found = repo
        .find_by_hostname(tenant_id, key)
        .await
        .map_err(internal)?;
    match found.len() {
        0 => Err((StatusCode::NOT_FOUND, format!("no host named '{key}'")).into_response()),
        1 => Ok(found.remove(0)),
        _ => Err((
            StatusCode::CONFLICT,
            format!(
                "{} hosts are named '{key}'; name one by id: {}",
                found.len(),
                found
                    .iter()
                    .map(|h| h.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
            .into_response()),
    }
}

struct Evidence {
    host: HostContext,
    check: Option<(FailureContextRow, FailureReport)>,
    snapshot: Option<(FailureContextRow, FailureReport)>,
    facts: Vec<FactsDocument>,
}

/// Everything the explanation is built from. Best-effort below the reports: a host whose tags
/// or facts cannot be read still gets an explanation, with less to go on.
async fn gather(
    state: &AppState,
    tenant_id: i64,
    host: &Host,
    error: &str,
    check: Option<&str>,
) -> anyhow::Result<Evidence> {
    let repo = FailureContextRepo::new(&state.db);
    let rows = repo
        .list_for_host(tenant_id, &host.id, MATCH_WINDOW)
        .await?;
    let decrypt = |row: &FailureContextRow| -> Option<(FailureContextRow, FailureReport)> {
        // Decrypted under exactly the purpose it was written with: a payload moved onto
        // another host's row fails here rather than explaining that host's error.
        let plain = state
            .config
            .master_key
            .decrypt(
                Purpose::FailureContext {
                    tenant_id,
                    host_id: &host.id,
                },
                &row.payload_encrypted,
            )
            .map_err(|e| tracing::error!(failure_id = %row.id, error = %e, "a stored report would not decrypt"))
            .ok()?;
        let report = serde_json::from_slice(&plain).ok()?;
        Some((row.clone(), report))
    };

    let matched = match_check(&rows, check, error);
    let check = matched.and_then(decrypt);
    // The latest snapshot is the newest captured one, whichever check it came with — and when
    // that is the matched report, it is that report rather than a second decrypt of it.
    let snapshot = match rows.iter().find(|r| r.context_state == "captured") {
        Some(r) if check.as_ref().is_some_and(|(c, _)| c.id == r.id) => check.clone(),
        Some(r) => decrypt(r),
        None => None,
    };

    let tags = HostTagsRepo::new(&state.db)
        .list_for_host(tenant_id, &host.id)
        .await
        .map(|tags| tags.into_iter().map(|(k, v, _source)| (k, v)).collect())
        .unwrap_or_default();

    Ok(Evidence {
        host: HostContext {
            host_id: host.id.clone(),
            hostname: host.hostname.clone(),
            tags,
        },
        check,
        snapshot,
        facts: load_facts(state, tenant_id, &host.id).await,
    })
}

/// The report the error is about.
///
/// With `check`, the newest report whose command or alias is that name. Without it, the
/// newest report whose alias — or failing that, command — appears in the error text, so a
/// pasted `web01/disk_c is CRITICAL` finds `disk_c` without being told. An alias is preferred
/// over a command because it names one instance: several checks share `check_drivesize`.
fn match_check<'r>(
    rows: &'r [FailureContextRow],
    check: Option<&str>,
    error: &str,
) -> Option<&'r FailureContextRow> {
    if let Some(name) = check.map(str::trim).filter(|c| !c.is_empty()) {
        return rows
            .iter()
            .find(|r| r.alias.eq_ignore_ascii_case(name) || r.command.eq_ignore_ascii_case(name));
    }
    let haystack = error.to_ascii_lowercase();
    let named = |s: &str| s.len() >= MIN_MATCH_LEN && haystack.contains(&s.to_ascii_lowercase());
    rows.iter()
        .find(|r| named(&r.alias))
        .or_else(|| rows.iter().find(|r| named(&r.command)))
}

/// The host's facts: the agent's own document first, then every imported source.
async fn load_facts(state: &AppState, tenant_id: i64, host_id: &str) -> Vec<FactsDocument> {
    let repo = HostFactsRepo::new(&state.db);
    let mut stored = Vec::new();
    match repo.get(tenant_id, host_id, AGENT_SOURCE).await {
        Ok(Some(d)) => stored.push(d),
        Ok(None) => {}
        Err(e) => tracing::error!(error = %e, "reading agent facts failed"),
    }
    match repo
        .list_for_host_except(tenant_id, host_id, AGENT_SOURCE)
        .await
    {
        Ok(others) => stored.extend(others),
        Err(e) => tracing::error!(error = %e, "reading imported facts failed"),
    }
    stored
        .into_iter()
        .filter_map(|d| {
            let facts: serde_json::Value = serde_json::from_str(&d.facts_json).ok()?;
            // An empty document is "nothing enabled", not evidence.
            if facts.as_object().is_some_and(|o| o.is_empty()) {
                return None;
            }
            Some(FactsDocument {
                source: d.source,
                collected_at: d.collected_at,
                facts,
            })
        })
        .collect()
}

/// Resolve a tenant's model settings: their own row if they have one, otherwise the
/// process-wide default from the environment.
///
/// Returns `Ok(None)` when explanations are not configured or not enabled for this tenant —
/// the ordinary case, and not an error.
async fn resolve_config(state: &AppState, tenant_id: i64) -> anyhow::Result<Option<LlmConfig>> {
    if let Some(s) = TenantFailureSettingsRepo::new(&state.db)
        .get(tenant_id)
        .await?
    {
        if !s.explain_enabled {
            return Ok(None);
        }
        let Some(provider) = ProviderKind::parse(&s.provider) else {
            anyhow::bail!(
                "configured provider '{}' is not one this server knows",
                s.provider
            );
        };
        let api_key = match &s.api_key_encrypted {
            Some(blob) => {
                let plain = state
                    .config
                    .master_key
                    .decrypt(Purpose::TenantLlmApiKey { tenant_id }, blob)
                    .map_err(|e| anyhow::anyhow!("stored API key could not be decrypted: {e}"))?;
                Some(
                    String::from_utf8(plain)
                        .map_err(|_| anyhow::anyhow!("stored API key is not valid UTF-8"))?,
                )
            }
            None => None,
        };
        if provider.requires_api_key() && api_key.is_none() {
            anyhow::bail!(
                "provider '{}' needs an API key and none is stored",
                s.provider
            );
        }
        return Ok(Some(LlmConfig {
            provider,
            model: s.model,
            base_url: s.base_url,
            api_key,
            daily_call_budget: s.daily_call_budget,
        }));
    }

    // No per-tenant row: the on-prem path, where the operator configured the process.
    Ok(crate::llm::server_default().cloned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(id: &str, command: &str, alias: &str) -> FailureContextRow {
        FailureContextRow {
            id: id.into(),
            tenant_id: 1,
            host_id: "h".into(),
            command: command.into(),
            alias: alias.into(),
            status: 2,
            status_word: "CRITICAL".into(),
            message: String::new(),
            subject: String::new(),
            context_state: "captured".into(),
            metrics_count: 0,
            payload_encrypted: vec![],
            payload_bytes: 0,
            reported_at: 0,
        }
    }

    fn rows() -> Vec<FailureContextRow> {
        // Newest first, as the repository returns them.
        vec![
            row("cpu", "check_cpu", "cpu"),
            row("d", "check_drivesize", "disk_d"),
            row("c", "check_drivesize", "disk_c"),
        ]
    }

    #[test]
    fn a_named_check_is_matched_by_alias_or_command() {
        let r = rows();
        assert_eq!(match_check(&r, Some("disk_c"), "").unwrap().id, "c");
        assert_eq!(match_check(&r, Some("DISK_C"), "").unwrap().id, "c");
        assert_eq!(
            match_check(&r, Some("check_drivesize"), "").unwrap().id,
            "d",
            "a command shared by two checks names the newest"
        );
        assert!(
            match_check(&r, Some("check_mem"), "check_cpu is critical").is_none(),
            "a check that was named is not second-guessed from the text"
        );
    }

    #[test]
    fn a_check_named_in_the_error_is_found_without_being_told() {
        let r = rows();
        assert_eq!(
            match_check(&r, None, "PROBLEM: web01/disk_c is CRITICAL")
                .unwrap()
                .id,
            "c",
            "the alias names one instance of a shared command"
        );
        assert_eq!(
            match_check(&r, None, "check_drivesize returned CRITICAL")
                .unwrap()
                .id,
            "d"
        );
        assert!(match_check(&r, None, "the web site is slow").is_none());
    }

    #[test]
    fn a_short_alias_does_not_match_inside_other_words() {
        let r = vec![row("x", "check_x", "c")];
        assert!(match_check(&r, None, "critical: connection refused").is_none());
    }
}
