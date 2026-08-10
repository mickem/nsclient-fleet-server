-- 0002_magic_links.sql
--
-- Single-use email-bound tokens for sign-in. We store the SHA-256 of the token, never the token
-- itself, so a DB leak does not expose live magic links.

CREATE TABLE magic_links (
    token_hash  TEXT PRIMARY KEY,
    tenant_id   INTEGER NOT NULL REFERENCES tenants(id),
    user_id     INTEGER NOT NULL REFERENCES users(id),
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    created_at  INTEGER NOT NULL
);
CREATE INDEX idx_magic_links_tenant  ON magic_links(tenant_id);
CREATE INDEX idx_magic_links_expires ON magic_links(expires_at);
