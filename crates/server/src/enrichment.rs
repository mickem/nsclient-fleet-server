//! The background worker that asks a model to describe stored alerts.
//!
//! # Shape
//!
//! A loop, not a queue service: every few seconds it reads the oldest handful of rows in
//! `enrichment_state = 'pending'`, resolves each one's tenant configuration, makes the call,
//! and writes the answer back. There is no job table, no scheduler and no fan-out, because
//! the work is already bounded by the thing that bounds the alerts table — one row per
//! distinct problem per host — and a fleet's distinct problems arrive at human speed.
//!
//! # What the loop is careful about
//!
//! **Spend.** Every path that reaches a provider passes a per-tenant daily budget first, and
//! every attempt is counted against it whether or not it succeeded. A model call is the only
//! thing this server does that costs money per unit, and the failure mode — a fleet where
//! everything is broken, generating fingerprints faster than anyone reads them — is exactly
//! the one that would run up a bill unattended.
//!
//! **Not being a thundering herd.** [`BATCH`] rows per pass, sequential, with a pause
//! between passes. A provider rate limit is a retryable error and the row comes back later,
//! rather than the loop hammering until it is banned.
//!
//! **Consent.** A tenant with no configuration is not an error to retry; its rows are marked
//! `skipped` and left alone. Nothing about a customer's hosts is sent anywhere until someone
//! has configured where.

use std::time::Duration;

use fleet_core::aead::Purpose;
use fleet_core::alert::AlertContext;
use fleet_storage::{
    utc_day, AlertContextRepo, AlertContextRow, HostRepo, HostTagsRepo, TenantLlmRepo,
};

use crate::llm::prompt::{self, Description, HostContext};
use crate::llm::{LlmConfig, LlmError, LlmRequest, ProviderKind};
use crate::AppState;

/// Rows considered per pass.
const BATCH: i64 = 4;

/// Between passes when the last one found work. Short enough that an alert is described
/// while the operator is still looking at it, long enough that the loop is not a spin.
const BUSY_INTERVAL: Duration = Duration::from_secs(5);

/// Between passes when there was nothing to do, which is almost always.
const IDLE_INTERVAL: Duration = Duration::from_secs(30);

/// Tries before a row is given up on. Small: the errors that survive the retryable/terminal
/// split are transient by construction, and three spread over a widening backoff covers a
/// provider blip without turning a persistent fault into unbounded spend.
const MAX_ATTEMPTS: i64 = 3;

/// Backoff for attempt `n` (1-based): one minute, five, then twenty-five.
///
/// The clamp is to 1..=3 rather than 0..=3 because the exponent is `n - 1`, and a count of
/// zero would take that below zero. Nothing calls it with zero today; clamping at the
/// bottom is what keeps that true of the next caller as well.
fn backoff_secs(attempts: i64) -> i64 {
    let step = attempts.clamp(1, MAX_ATTEMPTS) as u32 - 1;
    60 * 5i64.pow(step)
}

/// Run forever. Spawned once at startup, like the housekeeping sweep.
pub async fn run(state: AppState) {
    // One client for the life of the process: connection reuse matters against a provider
    // that is on the other side of a TLS handshake, and the timeout is the bound that
    // stops a hung call owning the worker.
    let http = match reqwest::Client::builder()
        .timeout(crate::llm::CALL_TIMEOUT)
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "could not build the HTTP client; alert enrichment is disabled");
            return;
        }
    };

    loop {
        let did_work = match pass(&state, &http).await {
            Ok(n) => n > 0,
            Err(e) => {
                // A database error here is not a reason to stop describing alerts forever.
                tracing::error!(error = %e, "alert enrichment pass failed");
                false
            }
        };
        tokio::time::sleep(if did_work {
            BUSY_INTERVAL
        } else {
            IDLE_INTERVAL
        })
        .await;
    }
}

/// One pass. Returns how many rows were touched.
pub async fn pass(state: &AppState, http: &reqwest::Client) -> anyhow::Result<usize> {
    let repo = AlertContextRepo::new(&state.db);
    let rows = repo.take_pending(BATCH).await?;
    let n = rows.len();
    for row in rows {
        if let Err(e) = enrich_one(state, http, &row).await {
            // Already recorded against the row by `enrich_one`; this is the operator-facing
            // line. Deliberately not `error` for a transient failure: a provider having a
            // bad afternoon should not read like a broken server.
            tracing::debug!(alert_id = %row.id, error = %e, "alert enrichment attempt failed");
        }
    }
    Ok(n)
}

/// Resolve a tenant's model configuration: their own row if they have one, otherwise the
/// process-wide default from the environment.
///
/// Returns `Ok(None)` when enrichment is not configured or not enabled for this tenant —
/// the ordinary case, and not an error.
pub async fn resolve_config(state: &AppState, tenant_id: i64) -> anyhow::Result<Option<LlmConfig>> {
    if let Some(s) = TenantLlmRepo::new(&state.db).get(tenant_id).await? {
        if !s.enabled {
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

/// Describe one alert, recording the outcome against its row either way.
async fn enrich_one(
    state: &AppState,
    http: &reqwest::Client,
    row: &AlertContextRow,
) -> anyhow::Result<()> {
    let repo = AlertContextRepo::new(&state.db);

    let cfg = match resolve_config(state, row.tenant_id).await {
        Ok(Some(cfg)) => cfg,
        Ok(None) => {
            repo.mark_skipped(&row.id, "alert enrichment is not enabled for this tenant")
                .await?;
            return Ok(());
        }
        Err(e) => {
            // A broken configuration is the tenant's to fix, not something to retry into:
            // parking the row means turning it on later picks these up (`requeue_skipped`)
            // rather than finding them already burnt through their attempts.
            repo.mark_skipped(&row.id, &format!("alert enrichment is misconfigured: {e}"))
                .await?;
            return Ok(());
        }
    };

    let llm_repo = TenantLlmRepo::new(&state.db);
    let today = utc_day(fleet_core::time::now_unix());
    let spent = llm_repo.usage(row.tenant_id, today).await?.calls;
    if spent >= cfg.daily_call_budget {
        repo.mark_skipped(
            &row.id,
            &format!(
                "the daily model-call budget for this tenant ({}) is spent; enrichment resumes tomorrow",
                cfg.daily_call_budget
            ),
        )
        .await?;
        return Ok(());
    }

    // Decrypt under exactly the purpose it was written with: a payload moved onto another
    // host's row fails here rather than being described as that host's problem.
    let plain = state.config.master_key.decrypt(
        Purpose::AlertContext {
            tenant_id: row.tenant_id,
            host_id: &row.host_id,
        },
        &row.payload_encrypted,
    )?;
    let alert: AlertContext = serde_json::from_slice(&plain)?;

    let host_ctx = host_context(state, row).await;
    let req = LlmRequest {
        system: prompt::SYSTEM_PROMPT.to_string(),
        user: prompt::build_user_message(&alert, &host_ctx),
        schema: prompt::answer_schema(),
        max_output_tokens: prompt::MAX_OUTPUT_TOKENS,
    };

    let provider = cfg.provider_impl();
    let result = provider.complete(http, &cfg, &req).await;

    // Counted before the result is inspected: the request was made, and a provider that
    // read the prompt before failing has usually billed for it.
    let (in_tok, out_tok) = match &result {
        Ok(r) => (r.input_tokens.unwrap_or(0), r.output_tokens.unwrap_or(0)),
        Err(_) => (0, 0),
    };
    llm_repo
        .record_call(row.tenant_id, today, result.is_err(), in_tok, out_tok)
        .await?;

    let response = match result {
        Ok(r) => r,
        Err(e) => return Err(record_failure(&repo, row, e).await),
    };

    let description =
        match crate::llm::extract_json(&response.text).and_then(|v| Description::from_json(&v)) {
            Ok(d) => d,
            Err(e) => return Err(record_failure(&repo, row, e).await),
        };

    let ciphertext = state.config.master_key.encrypt(
        Purpose::AlertContext {
            tenant_id: row.tenant_id,
            host_id: &row.host_id,
        },
        &serde_json::to_vec(&description)?,
    );
    repo.store_enrichment(
        &row.id,
        cfg.provider.as_str(),
        &cfg.model,
        &ciphertext,
        response.input_tokens,
        response.output_tokens,
    )
    .await?;

    tracing::info!(
        alert_id = %row.id,
        tenant_id = row.tenant_id,
        provider = cfg.provider.as_str(),
        model = %cfg.model,
        // Deliberately not the description itself: it restates evidence from a customer's
        // host, and the journal is not where that belongs.
        input_tokens = response.input_tokens.unwrap_or(0),
        output_tokens = response.output_tokens.unwrap_or(0),
        "described an alert"
    );
    Ok(())
}

/// Write a failure to the row, respecting the retryable/terminal split.
///
/// A terminal error jumps straight to the attempt limit: there is no point serving out a
/// backoff before giving up on a revoked key.
async fn record_failure(
    repo: &AlertContextRepo<'_>,
    row: &AlertContextRow,
    err: LlmError,
) -> anyhow::Error {
    let retryable = err.retryable();
    let message = err.to_string();
    let (max_attempts, retry_after) = if retryable {
        (MAX_ATTEMPTS, backoff_secs(row.enrichment_attempts + 1))
    } else {
        (row.enrichment_attempts + 1, 0)
    };
    if let Err(e) = repo
        .record_failure(&row.id, &message, max_attempts, retry_after)
        .await
    {
        return anyhow::anyhow!("{message} (and recording it failed: {e})");
    }
    if !retryable {
        // Worth an operator's attention: nothing will retry this, and the same cause will
        // stop every other alert for this tenant.
        tracing::warn!(
            alert_id = %row.id,
            tenant_id = row.tenant_id,
            error = %message,
            "alert enrichment failed permanently; fix the provider configuration and re-run it"
        );
    }
    anyhow::anyhow!(message)
}

/// The facts the server knows about the host, which the agent did not send.
///
/// Best-effort: a host whose name or tags cannot be read still gets described, just with
/// less to go on. Failing the enrichment over it would be trading the whole answer for a
/// nicety.
async fn host_context(state: &AppState, row: &AlertContextRow) -> HostContext {
    let descriptor = HostRepo::new(&state.db)
        .get(row.tenant_id, &row.host_id)
        .await
        .ok()
        .flatten()
        .and_then(|h| h.hostname);

    let tags = HostTagsRepo::new(&state.db)
        .list_for_host(row.tenant_id, &row.host_id)
        .await
        .map(|tags| {
            tags.into_iter()
                .map(|(k, v, _source)| (k, v))
                .collect::<std::collections::BTreeMap<_, _>>()
        })
        .unwrap_or_default();

    HostContext {
        host_id: row.host_id.clone(),
        descriptor,
        tags,
        occurrences: row.occurrences,
        first_seen_at: row.first_seen_at,
        last_seen_at: row.last_seen_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_widens_and_is_bounded() {
        assert_eq!(backoff_secs(1), 60);
        assert_eq!(backoff_secs(2), 300);
        assert_eq!(backoff_secs(3), 1500);
        // Past the attempt limit the row is terminal anyway, but the arithmetic must not
        // overflow if it is ever called with a larger count.
        assert_eq!(backoff_secs(9), 1500);
        assert_eq!(backoff_secs(0), 60);
    }
}
