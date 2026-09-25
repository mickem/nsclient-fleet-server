-- 0014_host_facts.sql
--
-- Host facts: the inventory document an agent uploads about the machine it runs on (OS,
-- hardware, network interfaces, volumes, installed software). Opt-in on the agent, one
-- document per host, up to about a megabyte.
--
-- The document itself only travels when it changed: every poll and state report carries
-- its hash, the server answers with the hash it holds, and the agent uploads on a miss.
--
-- `host_facts` holds the document, verbatim: `facts_hash` is the SHA-256 of exactly the
-- bytes in `facts_json`, and re-encoding them would break that. A host with no row has
-- never uploaded; one with the empty document `{}` has uploaded and has nothing enabled.
CREATE TABLE host_facts (
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id),
    host_id       TEXT NOT NULL REFERENCES hosts(id),
    facts_hash    TEXT NOT NULL,
    facts_json    TEXT NOT NULL,
    -- When the agent read the values (its own clock, ISO 8601), as it reported it.
    collected_at  TEXT,
    -- When we received this document (our clock).
    received_at   INTEGER NOT NULL,
    size_bytes    INTEGER NOT NULL,
    PRIMARY KEY (host_id)
);
CREATE INDEX idx_host_facts_tenant ON host_facts(tenant_id);

-- What changed between consecutive documents, computed on upload with list records matched
-- by id: "curl was removed", "bash went from 5.1 to 5.2". A bounded history per host — the
-- oldest rows are dropped on insert — not an archive of every document.
CREATE TABLE host_fact_changes (
    id            INTEGER PRIMARY KEY,
    tenant_id     INTEGER NOT NULL REFERENCES tenants(id),
    host_id       TEXT NOT NULL REFERENCES hosts(id),
    at            INTEGER NOT NULL,
    facts_hash    TEXT NOT NULL,
    -- {"initial": bool, "changes": [{path, kind, old?, new?}], "truncated": n}
    changes_json  TEXT NOT NULL
);
CREATE INDEX idx_host_fact_changes_tenant_host ON host_fact_changes(tenant_id, host_id, id);

-- The hash the agent last said it holds, from its polls and state reports. Next to the
-- stored document's hash this tells "up to date" from "the agent has a newer inventory we
-- have not received" and "nothing enabled on the host". NULL: the agent never sent one —
-- a build without facts support.
ALTER TABLE hosts ADD COLUMN facts_reported_hash TEXT;
