//! Tenant user management: list, invite, re-role, remove.
//!
//! Every route here requires `Role::can_manage_users`. Two rules keep a tenant from locking
//! itself out of its own control plane, which has no self-service recovery:
//!
//! 1. The owner cannot be re-roled or removed.
//! 2. Nobody can re-role or delete themselves.
//!
//! Together those are sufficient: a caller must already manage users to reach these routes,
//! and cannot act on their own row, so whatever else they do at least one manager — them —
//! is still standing when the request finishes. No "last admin" counter is needed, and one
//! would be unreachable code.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use fleet_core::user::Role;
use fleet_storage::UserRepo;
use serde::{Deserialize, Serialize};

use crate::auth::{forbidden, AuthedUser};
use crate::AppState;

#[derive(Serialize)]
pub struct UserView {
    pub id: i64,
    pub email: String,
    pub role: Role,
    pub created_at: i64,
    /// True for the caller's own row. The UI uses it to disable the controls that the
    /// self-modification guard would reject anyway.
    pub is_self: bool,
    /// Blocked by a platform admin. Read-only here — a tenant cannot block or unblock its own
    /// users — but shown so that "why can't they sign in?" has an answer on this page rather
    /// than a support ticket.
    pub blocked: bool,
}

#[derive(Deserialize)]
pub struct InviteBody {
    pub email: String,
    pub role: Role,
}

#[derive(Deserialize)]
pub struct SetRoleBody {
    pub role: Role,
}

pub async fn list(State(state): State<AppState>, who: AuthedUser) -> Response {
    if !who.role.can_manage_users() {
        return forbidden("manage users");
    }
    match UserRepo::new(&state.db).list(who.tenant_id).await {
        Ok(users) => Json(
            users
                .into_iter()
                .map(|u| UserView {
                    is_self: u.id == who.user_id,
                    blocked: u.is_blocked(),
                    id: u.id,
                    email: u.email,
                    role: u.role,
                    created_at: u.created_at,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(e) => {
            tracing::error!(error = %e, "user list failed");
            (StatusCode::INTERNAL_SERVER_ERROR, "list failed").into_response()
        }
    }
}

/// Create a user in the caller's tenant and email them a sign-in link.
///
/// The link is delivered only by email. Where SMTP is unconfigured the `EmailSender` logs it
/// under the `magic_link` target instead, so a dev box can still complete the flow from the
/// server log — but a production tenant without SMTP cannot onboard anyone, which is why
/// this returns 503 rather than pretending to have sent something.
pub async fn invite(
    State(state): State<AppState>,
    who: AuthedUser,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<InviteBody>,
) -> Response {
    if !who.role.can_manage_users() {
        return forbidden("manage users");
    }
    // On-prem authenticates exactly one user, from ON_PREM_ADMIN_EMAIL/_PASSWORD, and both
    // signup and magic links are disabled there. An invited user would be created but could
    // never sign in, so refuse instead of creating a dead row.
    if state.config.on_prem {
        return (
            StatusCode::NOT_FOUND,
            "user invitations are disabled in on-prem mode",
        )
            .into_response();
    }
    if !body.role.is_assignable() {
        return (StatusCode::BAD_REQUEST, "role cannot be assigned").into_response();
    }

    let email = body.email.trim().to_lowercase();
    if email.is_empty() || !email.contains('@') {
        return (StatusCode::BAD_REQUEST, "invalid email").into_response();
    }

    let users = UserRepo::new(&state.db);
    // Deliberately global, not per-tenant: `find_by_email` — which is what sign-in uses to
    // resolve an address to an account — takes the first match across all tenants. Allowing
    // the same address into a second tenant would make which tenant they land in arbitrary.
    if users.find_by_email(&email).await.unwrap_or(None).is_some() {
        return (StatusCode::CONFLICT, "email already registered").into_response();
    }

    let user = match users.create(who.tenant_id, &email, body.role).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(error = %e, "invite user create failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "create failed").into_response();
        }
    };

    // An address in PLATFORM_ADMIN_EMAILS that arrives by invitation rather than signup.
    crate::platform_admin_bootstrap(&state, &user).await;

    if let Err(e) = crate::auth::handlers::issue_and_send_link(
        &state,
        &user.email,
        who.tenant_id,
        user.id,
        addr,
    )
    .await
    {
        // The row exists but nothing was delivered. Roll it back rather than leave an
        // account the operator believes was invited and the invitee never hears about.
        tracing::error!(error = %e, %email, "invite email failed — removing the user row");
        let _ = users.delete(who.tenant_id, user.id).await;
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "could not send the invitation email — check SMTP configuration",
        )
            .into_response();
    }

    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "user.invited",
        "user",
        &user.id.to_string(),
        Some(&serde_json::json!({ "email": user.email, "role": user.role })),
    )
    .await;

    Json(UserView {
        id: user.id,
        email: user.email,
        role: user.role,
        created_at: user.created_at,
        is_self: false,
        blocked: false,
    })
    .into_response()
}

pub async fn set_role(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(user_id): Path<i64>,
    Json(body): Json<SetRoleBody>,
) -> Response {
    if !who.role.can_manage_users() {
        return forbidden("manage users");
    }
    if !body.role.is_assignable() {
        return (StatusCode::BAD_REQUEST, "role cannot be assigned").into_response();
    }
    if user_id == who.user_id {
        return (StatusCode::BAD_REQUEST, "you cannot change your own role").into_response();
    }

    let users = UserRepo::new(&state.db);
    let target = match users.get(who.tenant_id, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "user get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
        }
    };
    if target.role == Role::Owner {
        return (StatusCode::FORBIDDEN, "the owner's role cannot be changed").into_response();
    }

    match users.set_role(who.tenant_id, user_id, body.role).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "set_role failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "update failed").into_response();
        }
    }

    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "user.role_changed",
        "user",
        &user_id.to_string(),
        Some(&serde_json::json!({
            "email": target.email,
            "from": target.role,
            "to": body.role,
        })),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}

pub async fn delete_user(
    State(state): State<AppState>,
    who: AuthedUser,
    Path(user_id): Path<i64>,
) -> Response {
    if !who.role.can_manage_users() {
        return forbidden("manage users");
    }
    if user_id == who.user_id {
        return (StatusCode::BAD_REQUEST, "you cannot delete yourself").into_response();
    }

    let users = UserRepo::new(&state.db);
    let target = match users.get(who.tenant_id, user_id).await {
        Ok(Some(u)) => u,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "user get failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "lookup failed").into_response();
        }
    };
    if target.role == Role::Owner {
        return (
            StatusCode::FORBIDDEN,
            "the owner cannot be removed — it is the tenant's last resort",
        )
            .into_response();
    }

    match users.delete(who.tenant_id, user_id).await {
        Ok(true) => {}
        Ok(false) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => {
            tracing::error!(error = %e, "user delete failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "delete failed").into_response();
        }
    }

    crate::audit::record(
        &state,
        who.tenant_id,
        Some(who.user_id),
        "user.deleted",
        "user",
        &user_id.to_string(),
        Some(&serde_json::json!({ "email": target.email, "role": target.role })),
    )
    .await;

    StatusCode::NO_CONTENT.into_response()
}
