//! API keys: long-lived bearer tokens for scripting the operator API.
//!
//! A key is bound to a user and carries whatever that user's role currently allows — see
//! `auth::middleware::from_api_key`. There is no separate permission set to configure or
//! keep in sync, which means the answer to "what can this key do?" is always "whatever its
//! owner can do", and re-roling or deleting the owner takes effect on the key's next request.
//!
//! Consequences worth being deliberate about:
//!   * A key held by an admin is an admin credential. Issue keys from an `add_hosts` account
//!     when all the script needs is to provision installers.
//!   * Any signed-in user may manage their own keys, whatever their role — a `view_only` key
//!     is a read-only key, which is a perfectly good thing to want.
//!   * Keys are private to their owner. Nobody, admin included, can list or revoke someone
//!     else's; deleting the user takes their keys with them.
//!   * A key cannot mint another key. Otherwise revoking a leaked one revokes nothing: its
//!     holder makes a replacement first, and the replacement outlives the revocation.
//!   * A key cannot reach the platform console, whatever flag its owner carries. See the
//!     `PlatformAdmin` extractor.

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::api_key::{prefix_of, TOKEN_PREFIX};
use fleet_storage::ApiKeyRepo;
use serde::{Deserialize, Serialize};

use crate::auth::{
    tokens::{hash_token, random_token},
    AuthedUser, Credential,
};
use crate::AppState;

const MAX_NAME_LEN: usize = 128;
/// Enough for a person and their scripts, low enough that a runaway loop is visible rather
/// than unbounded.
const MAX_KEYS_PER_USER: usize = 25;
/// Longest expiry a key may be given. Two years is past any sensible rotation interval
/// while still being an end.
const MAX_EXPIRY_DAYS: i64 = 730;

#[derive(Serialize)]
pub struct ApiKeyView {
    pub id: String,
    pub name: String,
    /// e.g. `nsk_a1B2c3D4` — identifies the key without being usable as one.
    pub token_prefix: String,
    pub created_at: i64,
    pub last_used_at: Option<i64>,
    /// `null` for a key that never expires.
    pub expires_at: Option<i64>,
}

/// The only response that ever contains the secret. Issued once, at creation; there is no
/// endpoint that can return it again because only its hash is stored.
#[derive(Serialize)]
pub struct CreatedApiKey {
    #[serde(flatten)]
    pub key: ApiKeyView,
    pub token: String,
}

#[derive(Deserialize)]
pub struct CreateBody {
    pub name: String,
    /// Omit, or send null, for a key that never expires.
    #[serde(default)]
    pub expires_in_days: Option<i64>,
}

fn view(k: fleet_core::api_key::ApiKey) -> ApiKeyView {
    ApiKeyView {
        id: k.id,
        name: k.name,
        token_prefix: k.token_prefix,
        created_at: k.created_at,
        last_used_at: k.last_used_at,
        expires_at: k.expires_at,
    }
}

pub async fn list(State(state): State<AppState>, who: AuthedUser) -> Response {
    match ApiKeyRepo::new(&state.db)
        .list_for_user(who.tenant_id, who.user_id)
        .await
    {
        Ok(keys) => Json(keys.into_iter().map(view).collect::<Vec<_>>()).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "api key list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "list failed").into_response()
        }
    }
}

pub async fn create(
    State(state): State<AppState>,
    who: AuthedUser,
    Json(body): Json<CreateBody>,
) -> Response {
    // A key cannot mint another key. Without this, revoking a leaked key revokes nothing:
    // whoever holds it creates a replacement first, and the replacement survives the
    // revocation — so the only way back is to delete the owner.
    if who.via != Credential::Session {
        return (
            StatusCode::FORBIDDEN,
            "API keys are created from a signed-in session, not with another API key",
        )
            .into_response();
    }

    let name = body.name.trim();
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return (StatusCode::BAD_REQUEST, "invalid name").into_response();
    }

    let expires_at = match body.expires_in_days {
        None => None,
        Some(d) if (1..=MAX_EXPIRY_DAYS).contains(&d) => {
            Some(fleet_core::time::now_unix() + d * 86_400)
        }
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("expires_in_days must be between 1 and {MAX_EXPIRY_DAYS}"),
            )
                .into_response()
        }
    };

    let keys = ApiKeyRepo::new(&state.db);
    match keys.list_for_user(who.tenant_id, who.user_id).await {
        Ok(existing) if existing.len() >= MAX_KEYS_PER_USER => {
            return (
                StatusCode::CONFLICT,
                "too many API keys — delete one before creating another",
            )
                .into_response();
        }
        Ok(_) => {}
        Err(e) => {
            tracing::error!(error = %e, "api key count failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    }

    let token = format!("{TOKEN_PREFIX}{}", random_token());
    let key = match keys
        .create(
            who.tenant_id,
            who.user_id,
            name,
            &hash_token(&token),
            &prefix_of(&token),
            expires_at,
        )
        .await
    {
        Ok(k) => k,
        Err(e) => {
            tracing::error!(error = %e, "api key create failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    };

    // The token is deliberately absent from the audit metadata — that table is readable by
    // every user in the tenant.
    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "api_key.created",
        "api_key",
        &key.id,
        Some(&serde_json::json!({
            "name": key.name, "prefix": key.token_prefix, "expires_at": key.expires_at,
        })),
    )
    .await;

    Json(CreatedApiKey {
        key: view(key),
        token,
    })
    .into_response()
}

pub async fn delete_key(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(id): Path<String>,
) -> Response {
    match ApiKeyRepo::new(&state.db)
        .delete(who.tenant_id, who.user_id, &id)
        .await
    {
        Ok(true) => {}
        // Also the answer when the key belongs to somebody else: the delete is scoped to the
        // caller, so another user's key is indistinguishable from one that does not exist.
        Ok(false) => return (StatusCode::NOT_FOUND, "key not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "api key delete failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response();
        }
    }

    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "api_key.revoked",
        "api_key",
        &id,
        None,
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}
