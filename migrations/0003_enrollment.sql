-- 0003_enrollment.sql
--
-- Per-tenant secrets (CA + bundle-signing key) and host bootstrap state.

CREATE TABLE tenant_secrets (
    tenant_id                    INTEGER PRIMARY KEY REFERENCES tenants(id),
    ca_cert_pem                  TEXT NOT NULL,
    ca_key_encrypted             BLOB NOT NULL,
    ca_subject_dn                TEXT NOT NULL UNIQUE,
    bundle_signing_pub_pem       TEXT NOT NULL,
    bundle_signing_key_encrypted BLOB NOT NULL,
    created_at                   INTEGER NOT NULL
);

ALTER TABLE hosts ADD COLUMN bootstrap_nonce_hash TEXT;
ALTER TABLE hosts ADD COLUMN bootstrap_expires_at INTEGER;
CREATE INDEX idx_hosts_bootstrap_nonce ON hosts(bootstrap_nonce_hash);
