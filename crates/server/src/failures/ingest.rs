//! `POST /agent/v1/failure-context` — taking one failure report from an agent.
//!
//! # Why the status code is part of the contract
//!
//! The agent reads our answer as policy, and each class means something it then *does*
//! (NSClient++ `service/fleet_sync.cpp`):
//!
//! | answer | what the agent does |
//! |---|---|
//! | `2xx` | records the report as sent, and persists the time so a restart does not re-send |
//! | `404` / `410` | concludes we have no such route and stops reporting until a poll advertises again |
//! | `413` | **drops the report permanently** — it will not be retried |
//! | `429` / `503` | stays quiet for the next turn; a `Retry-After` holds every report |
//! | other `4xx`/`5xx` | retries after 1 min, doubling to an hour |
//!
//! Two consequences shape this handler. A refusal is expensive — a `4xx` loses the failure
//! outright — so everything that *can* be clamped is clamped rather than refused, and the
//! only 400 is a report with no command in it, which there is nothing to store under.
//! And over-capacity has to be a `429` with a `Retry-After`, never a silent accept: the
//! agent then backs off, which is the behaviour we want, and nothing is lost.
//!
//! Success is `202`, not `200`: the report is stored as evidence, and nothing is done with
//! it until someone asks for an error on this host to be explained.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::crypto::aead::Purpose;
use fleet_core::failures::{new_failure_id, FailureReport, MAX_REPORT_BYTES};
use fleet_storage::{FailureContextRepo, NewFailureContext};
use serde::Serialize;

use crate::transport::mtls::PeerHostContext;
use crate::AppState;

/// Checks one host may have a report on file for at once.
///
/// The bound that holds when retention does not. A check whose alias carries something
/// variable — a timestamp, a PID, a generated name — is a new key on every report, and
/// every one of those rows is too new to sweep.
pub const MAX_FAILURES_PER_HOST: i64 = 200;

/// How long a report nobody has refreshed is kept.
pub const RETENTION_SECS: i64 = 30 * 86_400;

/// What the agent gets back. It does not read the body — only the status — but a human
/// debugging with curl does.
#[derive(Serialize)]
pub struct IngestResponse {
    pub stored: bool,
    /// The row the report is stored as: the same id every time this check reports.
    pub id: String,
}

pub async fn ingest(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    body: axum::body::Bytes,
) -> Response {
    // Checked against the raw bytes, before parsing. The per-field caps inside
    // `FailureReport::normalize` bound a well-formed report; this bounds a hostile one, and
    // it costs a length comparison. The agent drops a 413 rather than retrying it, so the
    // cap is set well above the ~120 KB a real snapshot renders to.
    if body.len() > MAX_REPORT_BYTES {
        tracing::info!(
            host_id = %ctx.host_id,
            bytes = body.len(),
            limit = MAX_REPORT_BYTES,
            "refused an oversized failure report"
        );
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "a failure report may be at most {MAX_REPORT_BYTES} bytes; \
                 lower what the metrics snapshot holds or turn `capture metrics` off"
            ),
        )
            .into_response();
    }

    let mut report: FailureReport = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            // A 400 costs the agent this failure. Worth a log line naming the parse error,
            // because the only way this happens is an agent build we do not understand.
            tracing::info!(host_id = %ctx.host_id, error = %e, "refused a malformed failure report");
            return (
                StatusCode::BAD_REQUEST,
                format!("malformed failure report: {e}"),
            )
                .into_response();
        }
    };
    if let Err(e) = report.normalize() {
        tracing::info!(host_id = %ctx.host_id, error = %e, "refused an unusable failure report");
        return (StatusCode::BAD_REQUEST, e.to_string()).into_response();
    }

    let repo = FailureContextRepo::new(&state.db);

    let payload = match serde_json::to_vec(&report) {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "could not re-serialise a report we just parsed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let ciphertext = state.config.master_key.encrypt(
        Purpose::FailureContext {
            tenant_id: ctx.tenant_id,
            host_id: &ctx.host_id,
        },
        &payload,
    );

    let f = &report.failure;
    let stored = match repo
        .upsert(NewFailureContext {
            id: &new_failure_id(),
            tenant_id: ctx.tenant_id,
            host_id: &ctx.host_id,
            command: &f.command,
            alias: &f.alias,
            status: f.status,
            status_word: f.status_word(),
            message: &f.summary_line(),
            subject: &f.subject,
            context_state: report.context.state.as_str(),
            metrics_count: report.context.metrics.len() as i64,
            payload_encrypted: &ciphertext,
            payload_bytes: payload.len() as i64,
        })
        .await
    {
        Ok(o) => o,
        Err(e) => {
            tracing::error!(error = %e, host_id = %ctx.host_id, "storing a failure report failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };

    // A count per report, and a delete only when over the cap: in the steady state a host
    // reports the same few checks over and over and never reaches it.
    match repo.count_for_host(ctx.tenant_id, &ctx.host_id).await {
        Ok(n) if n > MAX_FAILURES_PER_HOST => {
            match repo
                .trim_host(ctx.tenant_id, &ctx.host_id, MAX_FAILURES_PER_HOST)
                .await
            {
                Ok(removed) if removed > 0 => tracing::info!(
                    host_id = %ctx.host_id,
                    removed,
                    "trimmed a host's oldest reports at the per-host cap"
                ),
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "trimming a host's reports failed"),
            }
        }
        Ok(_) => {}
        Err(e) => tracing::error!(error = %e, "counting a host's reports failed"),
    }

    (
        StatusCode::ACCEPTED,
        Json(IngestResponse {
            stored: true,
            id: stored,
        }),
    )
        .into_response()
}
