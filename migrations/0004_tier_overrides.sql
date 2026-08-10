-- 0004_tier_overrides.sql
--
-- Per-tenant tier overrides. NULL means "use the base tier limits unchanged".
-- When set, the JSON is a partial subset of TierLimits fields (e.g. {"max_hosts": 100})
-- and is overlaid on top of the base tier at lookup time. Unknown keys are ignored.

ALTER TABLE tenants ADD COLUMN tier_overrides_json TEXT;
