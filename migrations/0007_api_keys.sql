-- 0007_api_keys.sql
--
-- Long-lived bearer tokens bound to a user, for scripting the API (`curl -H "Authorization:
-- Bearer …"`). A key carries exactly its owner's role — there is no separate permission set
-- to keep in sync, and revoking access is either deleting the key or re-roling the user.
--
-- Only the SHA-256 of the token is stored, as with sessions and magic links: the plaintext is
-- shown once at creation and is unrecoverable afterwards. `token_prefix` holds the first few
-- characters so a key can still be recognised in a list.
--
-- Purely additive — no table rebuild, unlike 0006.

CREATE TABLE api_keys (
    id            TEXT PRIMARY KEY,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id),
    user_id       INTEGER NOT NULL REFERENCES users(id),
    name          TEXT NOT NULL,
    token_hash    TEXT NOT NULL UNIQUE,
    token_prefix  TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER
);

CREATE INDEX idx_api_keys_owner ON api_keys(tenant_id, user_id);
CREATE UNIQUE INDEX idx_api_keys_hash ON api_keys(token_hash);
