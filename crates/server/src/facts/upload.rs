use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::facts::{self, AGENT_SOURCE};
use fleet_core::time::now_unix;
use fleet_storage::{HostFactsRepo, ReplaceOutcome};
use futures_util::StreamExt;
use std::sync::Arc;

use super::exchange::{empty_over_inventory, EmptyOverInventory};
use super::{store, with_header};
use crate::transport::mtls::PeerHostContext;
use crate::AppState;

/// Largest upload body accepted. The agent caps its own document at `[/settings/facts] max
/// size`, a megabyte by default; this leaves room for an operator who raised that, while a
/// larger body is refused with 413 — which the agent reports once, naming the sets to turn
/// off, and does not retry until the document changes.
pub const MAX_FACTS_BODY_BYTES: usize = 4 * 1024 * 1024;

/// A verified upload, owned so it can come back from a blocking task.
struct Upload {
    facts_hash: String,
    collected_at: Option<String>,
    facts: Arc<str>,
}

enum BodyError {
    /// Over the limit. `drained`: the rest was read and discarded, so the refusal reaches
    /// the client; otherwise the connection has to be closed after it.
    TooLarge {
        drained: bool,
    },
    Unreadable,
}

/// How much of an oversized body is read and discarded so that the client, still writing
/// it, sees the 413 rather than a connection reset — which it would take for a network
/// error, and resend the document on every poll. Past this, the connection is closed.
const MAX_DRAINED_BYTES: usize = 4 * MAX_FACTS_BODY_BYTES;

/// The whole body, if it is no larger than `limit`. A larger one is drained (up to
/// [`MAX_DRAINED_BYTES`]) without being kept; a `Content-Length` that already says it is
/// too large skips the buffering, and one past the drain limit skips the reading.
async fn read_capped(headers: &HeaderMap, body: Body, limit: usize) -> Result<Bytes, BodyError> {
    let declared = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > MAX_DRAINED_BYTES) {
        return Err(BodyError::TooLarge { drained: false });
    }
    let mut stream = body.into_data_stream();
    let mut buf = Vec::new();
    let mut seen = declared.filter(|&n| n > limit).map_or(0, |_| limit + 1);
    let mut keep = seen == 0;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| BodyError::Unreadable)?;
        seen += chunk.len();
        if seen > MAX_DRAINED_BYTES {
            return Err(BodyError::TooLarge { drained: false });
        }
        if keep && seen > limit {
            keep = false;
            buf = Vec::new();
        }
        if keep {
            buf.extend_from_slice(&chunk);
        }
    }
    if keep {
        Ok(Bytes::from(buf))
    } else {
        Err(BodyError::TooLarge { drained: true })
    }
}

/// Refuse an upload, and record that it was: the agent does not retry a refused document,
/// so without the record the host would read as "inventory on its way" until its inventory
/// next changes.
///
/// `hash`: the refused document's own, when the body said it; otherwise the refusal is
/// recorded against the hash the agent last reported, which is the document it was sending.
async fn refuse(
    repo: &HostFactsRepo<'_>,
    ctx: &PeerHostContext,
    status: StatusCode,
    hash: Option<&str>,
    message: &str,
) -> Response {
    if let Err(e) = repo
        .record_refusal(ctx.tenant_id, &ctx.host_id, status.as_u16(), hash)
        .await
    {
        tracing::error!(error = %e, "recording a facts refusal failed");
    }
    (status, message.to_owned()).into_response()
}

/// `POST /agent/v1/facts`: store the host's document.
///
/// The body is read as bytes, not through `Json`, because the hash covers the `facts` value
/// exactly as sent and is verified — and stored — against those bytes. It is read here
/// rather than through a body-limit layer so that an oversized one reaches this handler and
/// its refusal is recorded like any other.
pub async fn upload(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let repo = HostFactsRepo::new(&state.db);
    let body = match read_capped(&headers, body, MAX_FACTS_BODY_BYTES).await {
        Ok(b) => b,
        Err(BodyError::TooLarge { drained }) => {
            tracing::info!(host_id = %ctx.host_id, "refused an oversized facts upload");
            let mut response = refuse(
                &repo,
                &ctx,
                StatusCode::PAYLOAD_TOO_LARGE,
                None,
                "facts upload too large",
            )
            .await;
            if !drained {
                // Unread body left on the connection: it cannot carry another request.
                response
                    .headers_mut()
                    .insert(header::CONNECTION, HeaderValue::from_static("close"));
            }
            return response;
        }
        // The connection failed mid-body: nothing was refused. 503 is the status the agent
        // retries on its next poll; a 400 would tell it never to send this document again.
        Err(BodyError::Unreadable) => {
            return (StatusCode::SERVICE_UNAVAILABLE, "body could not be read").into_response()
        }
    };
    // Hashing and parsing up to 4 MiB is CPU work: off the async workers.
    let parsed = tokio::task::spawn_blocking(move || {
        facts::parse_upload(&body).map(|u| Upload {
            facts_hash: u.facts_hash,
            collected_at: u.collected_at,
            facts: Arc::from(u.facts),
        })
    })
    .await;
    let upload = match parsed {
        Ok(Ok(u)) => u,
        Ok(Err(e)) => {
            tracing::info!(host_id = %ctx.host_id, error = %e, "rejected a facts upload");
            return refuse(
                &repo,
                &ctx,
                StatusCode::BAD_REQUEST,
                e.declared_hash(),
                &e.to_string(),
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "facts upload parse task failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let hashes = match repo.hashes(ctx.tenant_id, &ctx.host_id).await {
        Ok(Some(h)) => h,
        Ok(None) => return (StatusCode::NOT_FOUND, "host not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "facts hash lookup failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if hashes.held.as_deref() == Some(upload.facts_hash.as_str()) {
        // A re-send of what we already hold: answered from the hash alone, without walking
        // the document. Only its collection time can have moved.
        if let Some(collected_at) = upload.collected_at.as_deref() {
            if let Err(e) = repo
                .refresh_collected_at(
                    ctx.tenant_id,
                    &ctx.host_id,
                    AGENT_SOURCE,
                    &upload.facts_hash,
                    collected_at,
                )
                .await
            {
                tracing::error!(error = %e, "refreshing collected_at failed");
            }
        }
    } else if empty_over_inventory(&hashes, &upload.facts_hash, now_unix())
        == EmptyOverInventory::Pending
    {
        // An empty document over a real one waits out the same grace period as an empty
        // report does; the poll that ends it clears the inventory. Accepted, so the agent
        // does not retry it.
    } else {
        match store(
            &state,
            ctx.tenant_id,
            &ctx.host_id,
            AGENT_SOURCE,
            &upload.facts_hash,
            upload.facts.clone(),
            upload.collected_at.as_deref(),
        )
        .await
        {
            Ok(ReplaceOutcome::Stored) => tracing::info!(
                host_id = %ctx.host_id,
                facts_hash = %upload.facts_hash,
                size_bytes = upload.facts.len(),
                "stored host facts"
            ),
            Ok(ReplaceOutcome::Unchanged) => { /* a concurrent upload of the same document */ }
            Ok(ReplaceOutcome::Conflict) => {
                // The agent retries on its next poll; a 503 is "try again", not a refusal.
                tracing::warn!(host_id = %ctx.host_id, "facts upload kept racing another write");
                return (StatusCode::SERVICE_UNAVAILABLE, "busy").into_response();
            }
            Ok(ReplaceOutcome::NoHost) => {
                return (StatusCode::NOT_FOUND, "host not found").into_response()
            }
            Err(e) => {
                tracing::error!(error = %e, "storing host facts failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
            }
        }
    }
    // The agent obviously holds what it just sent.
    if let Err(e) = repo
        .set_reported_hash(ctx.tenant_id, &ctx.host_id, &upload.facts_hash)
        .await
    {
        tracing::error!(error = %e, "set_reported_hash failed");
    }

    let held = HeaderValue::from_str(&upload.facts_hash).ok();
    with_header(Json(serde_json::json!({})).into_response(), held)
}
