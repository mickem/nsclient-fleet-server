use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use fleet_core::crypto::encbundle;
use fleet_storage::BundlesRepo;

use crate::auth::AuthedUser;
use crate::transport::mtls::PeerHostContext;
use crate::AppState;

/// `GET /agent/v1/bundles/:id` — mTLS download. Authorization: the host's effective bundle set
/// must include this bundle (i.e., the host's tags match a group that has this bundle assigned).
/// `GET /api/bundles/:id/download` — the stored bytes, exactly as uploaded, for the
/// operator's browser. Plain bundles come back as the signed zip; encrypted bundles as the
/// NSEB1 envelope, which the browser decrypts with the tenant key for client-side editing.
/// No role gate beyond a session: this returns nothing the server itself could read that
/// `GET /api/bundles/:id/config` does not already expose.
pub async fn ui_download(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(bundle_id): Path<String>,
) -> Response {
    let row = match BundlesRepo::new(&state.db)
        .get(who.tenant_id, &bundle_id)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "bundle not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "bundle get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    let bytes = match state.bundle_store.get(who.tenant_id, &bundle_id).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, %bundle_id, "bundle store get failed");
            return (StatusCode::NOT_FOUND, "bundle bytes missing").into_response();
        }
    };
    let (content_type, ext) = if row.format == encbundle::FORMAT_ENC_V1 {
        ("application/octet-stream", "nseb")
    } else {
        ("application/zip", "zip")
    };
    // Uploaded names are only checked non-empty, so the filename is sanitized rather than
    // trusted into a header.
    let safe: String = format!("{}-{}", row.name, row.version)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mut resp = Response::new(Body::from(bytes));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    if let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{safe}.{ext}\"")) {
        resp.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    resp
}

pub async fn download(
    State(state): State<AppState>,
    axum::Extension(ctx): axum::Extension<PeerHostContext>,
    Path(bundle_id): Path<String>,
) -> Response {
    use crate::agent::desired_state::compute_desired_state;
    let ds = match compute_desired_state(&state, ctx.tenant_id, &ctx.host_id).await {
        Ok(d) => d,
        Err(e) => {
            tracing::error!(error = %e, "compute_desired_state failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "internal").into_response();
        }
    };
    if !ds.bundles.iter().any(|b| b.id == bundle_id) {
        return (StatusCode::FORBIDDEN, "bundle not assigned to this host").into_response();
    }

    match state.bundle_store.get(ctx.tenant_id, &bundle_id).await {
        Ok(bytes) => {
            let content_type = if encbundle::is_encrypted(&bytes) {
                "application/octet-stream"
            } else {
                "application/zip"
            };
            let mut resp = Response::new(Body::from(bytes));
            resp.headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            resp
        }
        Err(e) => {
            tracing::error!(error = %e, %bundle_id, "bundle store get failed");
            (StatusCode::NOT_FOUND, "bundle bytes missing").into_response()
        }
    }
}
