-- 0006_user_roles.sql
--
-- Widen users.role from ('owner','member') to the permission set the operator UI offers:
-- owner, admin, add_hosts, view_only.
--
-- SQLite cannot alter a CHECK constraint, so the table has to be rebuilt, and four tables
-- reference users(id): sessions, magic_links, host_overrides.updated_by_user and
-- audit_log.user_id. `DROP TABLE users` performs an implicit DELETE FROM, which orphans all
-- of them and fails with FOREIGN KEY constraint failed.
--
-- The usual escape (`PRAGMA foreign_keys=OFF`) is unavailable: sqlx-sqlite always runs a
-- migration inside a transaction, and that pragma is a no-op once a transaction is open.
-- `PRAGMA defer_foreign_keys=ON` is legal there but does not help — re-creating the parent
-- does not decrement the deferred violation counter, so COMMIT still fails.
--
-- So the references are cleared before the rebuild and restored after it, and the table is
-- never dropped while anything points at a live row:
--
--   * sessions and magic_links are deleted outright. Both are short-lived by construction —
--     the cost is that everyone signs in again, which is the right side to err on when the
--     permission model itself is changing.
--   * audit_log and host_overrides keep their attribution: the user ids are parked in temp
--     tables, nulled for the duration, and written back at the end.
--
-- Existing rows: 'owner' is carried over. Everything else becomes 'admin', NOT a lesser role
-- — before this migration there were no authorization checks at all, so every existing user
-- had full control. Mapping them down would silently revoke access people already have.

CREATE TABLE _m0006_audit_user (id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL);
INSERT INTO _m0006_audit_user (id, user_id)
SELECT id, user_id FROM audit_log WHERE user_id IS NOT NULL;

CREATE TABLE _m0006_override_user (host_id TEXT PRIMARY KEY, user_id INTEGER NOT NULL);
INSERT INTO _m0006_override_user (host_id, user_id)
SELECT host_id, updated_by_user FROM host_overrides WHERE updated_by_user IS NOT NULL;

UPDATE audit_log SET user_id = NULL;
UPDATE host_overrides SET updated_by_user = NULL;
DELETE FROM sessions;
DELETE FROM magic_links;

CREATE TABLE users_new (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'view_only'
                CHECK (role IN ('owner', 'admin', 'add_hosts', 'view_only')),
    created_at  INTEGER NOT NULL,
    UNIQUE (tenant_id, email)
);

INSERT INTO users_new (id, tenant_id, email, role, created_at)
SELECT id,
       tenant_id,
       email,
       CASE role WHEN 'owner' THEN 'owner' ELSE 'admin' END,
       created_at
FROM users;

DROP TABLE users;

ALTER TABLE users_new RENAME TO users;

CREATE INDEX idx_users_tenant ON users(tenant_id);

UPDATE audit_log
   SET user_id = (SELECT user_id FROM _m0006_audit_user WHERE _m0006_audit_user.id = audit_log.id)
 WHERE id IN (SELECT id FROM _m0006_audit_user);

UPDATE host_overrides
   SET updated_by_user = (SELECT user_id FROM _m0006_override_user
                           WHERE _m0006_override_user.host_id = host_overrides.host_id)
 WHERE host_id IN (SELECT host_id FROM _m0006_override_user);

DROP TABLE _m0006_audit_user;
DROP TABLE _m0006_override_user;
