-- 0009_local_config_present.sql
--
-- Agents now report whether the host carries configuration of its own that outranks what
-- the fleet sends (NSClient resolves a key from the local store first and only falls back
-- to the fleet-managed include, so a locally set key silently shadows ours).
--
-- Only the *fact* crosses the wire — never the local configuration itself, which routinely
-- holds credentials. This column stores exactly that fact and nothing more.
--
-- Deliberately nullable, giving three states rather than two:
--
--   NULL  no agent has ever reported on this. Either it has not checked in since the
--         column existed, or it runs a build that predates the field. "Unknown" and
--         "nothing local" are different answers, and defaulting to 0 would quietly turn
--         every silent agent into a claim we have no basis for.
--   0     reported: fully fleet-managed.
--   1     reported: partly self-managed — what the operator sees in the UI may not be
--         what is in force on the host.
--
-- Additive; existing rows keep NULL until their agent reports.

ALTER TABLE hosts ADD COLUMN local_config_present INTEGER
    CHECK (local_config_present IN (0, 1));
