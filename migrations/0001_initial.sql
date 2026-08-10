-- 0001_initial.sql
--
-- Tenancy invariant: every table except `tenants` carries `tenant_id INTEGER NOT NULL REFERENCES tenants(id)`,
-- denormalized even when reachable via FK chain. Every supporting index leads with `tenant_id`.
-- Foreign-key enforcement is per-connection (PRAGMA foreign_keys=ON in pool init).

CREATE TABLE tenants (
    id                INTEGER PRIMARY KEY,
    slug              TEXT NOT NULL UNIQUE,
    name              TEXT NOT NULL,
    tier              TEXT NOT NULL DEFAULT 'free',
    trial_expires_at  INTEGER,
    config_version    INTEGER NOT NULL DEFAULT 0,
    created_at        INTEGER NOT NULL
);

CREATE TABLE users (
    id          INTEGER PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    email       TEXT NOT NULL,
    role        TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'member')),
    created_at  INTEGER NOT NULL,
    UNIQUE (tenant_id, email)
);
CREATE INDEX idx_users_tenant ON users(tenant_id);

CREATE TABLE sessions (
    id            TEXT PRIMARY KEY,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id),
    user_id       INTEGER NOT NULL REFERENCES users(id),
    expires_at    INTEGER NOT NULL,
    last_used_at  INTEGER NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE INDEX idx_sessions_tenant_user ON sessions(tenant_id, user_id);
CREATE INDEX idx_sessions_expires     ON sessions(expires_at);

CREATE TABLE hosts (
    id                  TEXT PRIMARY KEY,
    tenant_id           INTEGER NOT NULL REFERENCES tenants(id),
    hostname            TEXT,
    os                  TEXT,
    enrolled_at         INTEGER,
    last_seen_at        INTEGER,
    current_state_hash  TEXT,
    created_at          INTEGER NOT NULL
);
CREATE INDEX idx_hosts_tenant ON hosts(tenant_id);

CREATE TABLE host_certs (
    tenant_id           INTEGER NOT NULL REFERENCES tenants(id),
    host_id             TEXT NOT NULL REFERENCES hosts(id),
    serial              TEXT NOT NULL UNIQUE,
    fingerprint_sha256  TEXT NOT NULL,
    issued_at           INTEGER NOT NULL,
    expires_at          INTEGER NOT NULL,
    revoked_at          INTEGER
);
CREATE INDEX idx_host_certs_tenant_host  ON host_certs(tenant_id, host_id);
CREATE INDEX idx_host_certs_fingerprint  ON host_certs(fingerprint_sha256);

CREATE TABLE host_tags (
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    host_id     TEXT NOT NULL REFERENCES hosts(id),
    key         TEXT NOT NULL,
    value       TEXT NOT NULL,
    source      TEXT NOT NULL CHECK (source IN ('manual', 'agent')),
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (host_id, key, source)
);
CREATE INDEX idx_host_tags_tenant_host       ON host_tags(tenant_id, host_id);
CREATE INDEX idx_host_tags_tenant_key_value  ON host_tags(tenant_id, key, value);

CREATE TABLE groups (
    id             TEXT PRIMARY KEY,
    tenant_id      INTEGER NOT NULL REFERENCES tenants(id),
    name           TEXT NOT NULL,
    selector_json  TEXT NOT NULL,
    created_at     INTEGER NOT NULL,
    UNIQUE (tenant_id, name)
);
CREATE INDEX idx_groups_tenant ON groups(tenant_id);

CREATE TABLE bundles (
    id           TEXT PRIMARY KEY,
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id),
    name         TEXT NOT NULL,
    version      TEXT NOT NULL,
    sha256       TEXT NOT NULL,
    size_bytes   INTEGER NOT NULL,
    signature    TEXT NOT NULL,
    uploaded_at  INTEGER NOT NULL,
    UNIQUE (tenant_id, name, version)
);
CREATE INDEX idx_bundles_tenant ON bundles(tenant_id);

CREATE TABLE bundle_assignments (
    tenant_id    INTEGER NOT NULL REFERENCES tenants(id),
    group_id     TEXT NOT NULL REFERENCES groups(id),
    bundle_id    TEXT NOT NULL REFERENCES bundles(id),
    priority     INTEGER NOT NULL DEFAULT 100,
    assigned_at  INTEGER NOT NULL,
    PRIMARY KEY (group_id, bundle_id)
);
CREATE INDEX idx_bundle_assignments_tenant_group  ON bundle_assignments(tenant_id, group_id);
CREATE INDEX idx_bundle_assignments_tenant_bundle ON bundle_assignments(tenant_id, bundle_id);

CREATE TABLE host_overrides (
    tenant_id        INTEGER NOT NULL REFERENCES tenants(id),
    host_id          TEXT NOT NULL REFERENCES hosts(id),
    patch_encrypted  BLOB NOT NULL,
    priority         INTEGER NOT NULL DEFAULT 1000,
    updated_at       INTEGER NOT NULL,
    updated_by_user  INTEGER REFERENCES users(id),
    PRIMARY KEY (host_id)
);
CREATE INDEX idx_host_overrides_tenant ON host_overrides(tenant_id);

CREATE TABLE metrics (
    tenant_id  INTEGER NOT NULL REFERENCES tenants(id),
    host_id    TEXT NOT NULL,
    ts         INTEGER NOT NULL,
    key        TEXT NOT NULL,
    value      REAL NOT NULL
);
CREATE INDEX idx_metrics_tenant_host_ts ON metrics(tenant_id, host_id, ts);

CREATE TABLE audit_log (
    id             INTEGER PRIMARY KEY,
    tenant_id      INTEGER NOT NULL REFERENCES tenants(id),
    user_id        INTEGER REFERENCES users(id),
    action         TEXT NOT NULL,
    target_type    TEXT NOT NULL,
    target_id      TEXT NOT NULL,
    metadata_json  TEXT,
    ts             INTEGER NOT NULL
);
CREATE INDEX idx_audit_tenant_ts ON audit_log(tenant_id, ts DESC);
