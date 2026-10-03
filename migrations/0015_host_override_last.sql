-- 0015_host_override_last.sql
--
-- Whether the host's agent applies the host override after the bundles.
--
-- The server sends a host's override separately from its bundles. Agents up to and
-- including NSClient++ 0.24.x merged the override first and the bundles on top, so any key
-- a bundle also set beat the override written for exactly that host. Agents with the fix
-- merge it last and say so on every state report; the console warns about an override on
-- any host whose agent does not.
--
--   NULL  no state report since this column existed.
--   0     reported without the field: an older agent, on which bundles win.
--   1     reported: the override is applied last and wins.

ALTER TABLE hosts ADD COLUMN host_override_last INTEGER
    CHECK (host_override_last IN (0, 1));
