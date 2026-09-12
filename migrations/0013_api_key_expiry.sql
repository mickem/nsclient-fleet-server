-- Optional expiry on API keys.
--
-- A key never expired, so a leaked one stayed a working credential until somebody noticed
-- and revoked it. Optional rather than mandatory: a key provisioning installers from CI has
-- no natural renewal moment, and forcing one would mean the deployment that forgets is the
-- one that breaks. NULL keeps the previous behaviour, and every existing key gets it.
--
-- Purely additive.
ALTER TABLE api_keys ADD COLUMN expires_at INTEGER;
