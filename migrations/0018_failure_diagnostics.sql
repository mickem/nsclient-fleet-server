-- 0018_failure_diagnostics.sql
--
-- A failure report can now carry the agent's diagnostics tables beside its metrics snapshot
-- (NSClient++ `capture diagnostics`): the processes using the most CPU and memory, the
-- services in trouble, the last errors in the system logs, where disk space went, the
-- failures before this one. Metrics say how much; the tables say what, by name.
--
-- The tables themselves are part of the report and live in `payload_encrypted` with the
-- rest of it: they name the processes and services running on a host. These two columns are
-- what a list needs to say whether a report has them, in the clear for the same reason
-- `context_state` and `metrics_count` are.

-- What became of the diagnostics snapshot: the agent's captured | evicted | too_large |
-- disabled | none, or `not_sent` for a report with no diagnostics in it at all, which is
-- what an agent that predates them sends and what every row stored before this migration
-- holds. Not a CHECK constraint, as for `context_state`.
ALTER TABLE failure_contexts ADD COLUMN diagnostics_state TEXT NOT NULL DEFAULT 'not_sent';
-- Tables in the stored report, 0 when there are none.
ALTER TABLE failure_contexts ADD COLUMN diagnostics_tables INTEGER NOT NULL DEFAULT 0;
