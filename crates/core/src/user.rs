use serde::{Deserialize, Serialize};

/// What a user is allowed to do inside their tenant.
///
/// Ordering is deliberate but not encoded as `Ord`: the permissions below are the contract,
/// not the variant order. Every authorization decision in the server goes through one of the
/// `can_*` methods so that adding a role means answering these questions once, here, rather
/// than hunting through handlers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// The account that created the tenant. Same powers as `Admin`; kept distinct so the
    /// last one cannot be removed or demoted, which is what stops a tenant locking itself out.
    Owner,
    /// Full control, including inviting and removing other users.
    Admin,
    /// Can see everything and add hosts. Cannot delete hosts, change configuration, or touch
    /// users — adding a host is the one write it gets.
    AddHosts,
    /// Read-only.
    ViewOnly,
}

impl Role {
    /// Parse a value stored in `users.role`.
    ///
    /// Fails closed: an unrecognised value yields `ViewOnly` rather than an error, so a row
    /// written by a future version can never be read as *more* privileged than it is. The
    /// CHECK constraint on the column means this should be unreachable in practice.
    pub fn from_db(s: &str) -> Self {
        match s {
            "owner" => Role::Owner,
            "admin" => Role::Admin,
            "add_hosts" => Role::AddHosts,
            _ => Role::ViewOnly,
        }
    }

    pub fn as_db(&self) -> &'static str {
        match self {
            Role::Owner => "owner",
            Role::Admin => "admin",
            Role::AddHosts => "add_hosts",
            Role::ViewOnly => "view_only",
        }
    }

    /// Invite, remove, and re-role other users.
    pub fn can_manage_users(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    /// Change fleet configuration: groups, bundles, assignments, host tags and overrides,
    /// and deleting hosts.
    pub fn can_write_config(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin)
    }

    /// Issue an enrollment token for a new host.
    pub fn can_add_hosts(&self) -> bool {
        matches!(self, Role::Owner | Role::Admin | Role::AddHosts)
    }

    /// Roles an admin may hand out. `Owner` is not in the list: it is established at signup
    /// and transferring it is a different operation from inviting someone.
    pub const ASSIGNABLE: [Role; 3] = [Role::Admin, Role::AddHosts, Role::ViewOnly];

    pub fn is_assignable(&self) -> bool {
        Self::ASSIGNABLE.contains(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub tenant_id: i64,
    pub email: String,
    pub role: Role,
    /// When a platform admin blocked this account, or `None` if it is allowed to sign in.
    ///
    /// Orthogonal to `role`: a blocked owner is still the owner, they just cannot
    /// authenticate. Enforced once, in the session layer, so it covers cookies and API keys
    /// alike rather than being a check every handler has to remember.
    pub blocked_at: Option<i64>,
    /// Cross-tenant privilege: may read and edit every tenant through `/api/platform/*`.
    /// Grants nothing extra inside the user's own tenant — `role` still decides that.
    pub is_platform_admin: bool,
    pub created_at: i64,
}

impl User {
    pub fn is_blocked(&self) -> bool {
        self.blocked_at.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_round_trip() {
        for role in [Role::Owner, Role::Admin, Role::AddHosts, Role::ViewOnly] {
            assert_eq!(Role::from_db(role.as_db()), role);
        }
    }

    /// The whole point of the split: `add_hosts` can add a host and nothing else, and
    /// `view_only` cannot write at all.
    #[test]
    fn permission_matrix() {
        assert!(Role::Owner.can_manage_users() && Role::Owner.can_write_config());
        assert!(Role::Admin.can_manage_users() && Role::Admin.can_write_config());

        assert!(Role::AddHosts.can_add_hosts());
        assert!(!Role::AddHosts.can_write_config());
        assert!(!Role::AddHosts.can_manage_users());

        assert!(!Role::ViewOnly.can_add_hosts());
        assert!(!Role::ViewOnly.can_write_config());
        assert!(!Role::ViewOnly.can_manage_users());
    }

    #[test]
    fn unknown_roles_fail_closed() {
        assert_eq!(Role::from_db("root"), Role::ViewOnly);
        assert_eq!(Role::from_db(""), Role::ViewOnly);
        // 'member' existed before 0006; the migration rewrites it, but a stale read must not
        // grant anything.
        assert_eq!(Role::from_db("member"), Role::ViewOnly);
    }

    #[test]
    fn owner_is_not_assignable_by_invite() {
        assert!(!Role::Owner.is_assignable());
        assert!(Role::Admin.is_assignable());
        assert!(Role::AddHosts.is_assignable());
        assert!(Role::ViewOnly.is_assignable());
    }
}
