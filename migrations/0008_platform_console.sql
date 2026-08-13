-- 0008_platform_console.sql
--
-- Everything the cross-tenant admin console needs. Three additions:
--
--   * users.is_platform_admin — the first privilege here that is NOT tenant-scoped. `role`
--     keeps its existing meaning (what you may do inside your own tenant); this flag is
--     orthogonal and grants exactly one thing: the /api/platform/* routes, which read and
--     edit every tenant's subscription and users. It is deliberately a column on `users`
--     rather than a fifth role, so that a platform admin is still an ordinary member of
--     their own tenant and nothing about the role checks has to change.
--
--   * users.blocked_at — a reversible alternative to deletion. A blocked user keeps their
--     row, their tenant membership and their audit attribution, but stops authenticating:
--     the session layer refuses both their cookie and any API key they own. NULL = allowed.
--     Deletion remains available for the cases where the row itself should go.
--
--   * platform_settings — process-wide switches with no tenant to hang off, which is why
--     this is the only table in the schema without a tenant_id. Key/value so the next
--     switch is an INSERT rather than a migration. Today it holds `signups_enabled`; an
--     absent row means the default (see `crate::platform::settings`), so a fresh database
--     needs no seed row.
--
-- Purely additive — no table rebuild, so unlike 0006 nobody is signed out by applying it,
-- and existing users default to not-blocked and not-platform-admin, which is the safe side
-- of both flags.

ALTER TABLE users ADD COLUMN is_platform_admin INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN blocked_at INTEGER;

CREATE TABLE platform_settings (
    key              TEXT PRIMARY KEY,
    value            TEXT NOT NULL,
    updated_at       INTEGER NOT NULL,
    -- Nullable and nulled on user deletion, exactly like audit_log.user_id: the setting
    -- outlives whoever last changed it.
    updated_by_user  INTEGER REFERENCES users(id)
);
