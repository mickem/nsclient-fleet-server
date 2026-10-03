-- 0016_host_override_template.sql
--
-- The UI template a host override was written with, so editing it reopens the same form.
-- Bundles keep theirs in bundle.toml; the override is a bare merge patch that goes to the
-- agent exactly as stored, so it has nowhere else to carry it.
--
--   NULL  written as plain INI (or before this column existed).

ALTER TABLE host_overrides ADD COLUMN template TEXT;
