-- 0005_drop_metrics.sql
--
-- Metrics were dropped from v1: a fleet *config* control plane doesn't need a
-- time-series store, and "just enough to know agents are alive" is already covered
-- by hosts.last_seen_at. Removing the ingest endpoint, retention job, and this table.
-- Re-introducing metrics later would add a fresh table + migration.

DROP TABLE IF EXISTS metrics;
