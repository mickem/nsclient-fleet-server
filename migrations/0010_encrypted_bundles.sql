-- Encrypted bundles (enc-v1): client-side AES-256-GCM envelopes the server stores
-- opaquely. The server never holds the key — only its fingerprint, for UX ("wrong key")
-- and rotation bookkeeping.

-- 'plain' = ordinary zip; 'enc-v1' = NSEB1 envelope (see fleet_core::encbundle).
ALTER TABLE bundles ADD COLUMN format TEXT NOT NULL DEFAULT 'plain';
-- First 8 bytes of SHA-256 of the encryption key, hex. NULL for plain bundles.
ALTER TABLE bundles ADD COLUMN key_fingerprint TEXT;

-- The tenant's current bundle-encryption-key fingerprint. One row per tenant; replaced on
-- rotation. The key itself exists only in operators' password managers and on agents.
CREATE TABLE tenant_bundle_keys (
    tenant_id        INTEGER PRIMARY KEY REFERENCES tenants(id),
    fingerprint      TEXT NOT NULL,
    created_at       INTEGER NOT NULL,
    created_by_user  INTEGER
);
