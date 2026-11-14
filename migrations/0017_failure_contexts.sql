-- 0017_failure_contexts.sql
--
-- Storage for the failure-context reports an enrolled agent sends (NSClient++
-- `POST /agent/v1/failure-context`), and the settings for explaining an error against them.
--
-- This server is not the monitoring system. The monitoring system raises the alert, tracks
-- how long it has been open and decides how bad it is; what this server adds is *context*:
-- when someone holding an error asks "why?", the host's latest metrics snapshot and facts
-- are here to explain it against. So a report is kept as evidence, not as an alert:
--
--   * **One row per check on a host**, keyed by (command, alias), holding only the newest
--     report. There is no occurrence count, no first-seen time and no status history —
--     those belong to the monitoring system, which already has them.
--   * **Nothing is described in the background.** A model is asked only when someone asks
--     to have an error explained (`POST /api/explain`), and the answer is returned rather
--     than stored.
--
-- The agent also paces itself — at most one report per host per interval, whatever is
-- failing — so the arrival rate is set by fleet size and the interval, and the row count by
-- how many distinct checks have failed. Neither grows with how long they stay failed.
--
-- `payload_encrypted` is a ciphertext for the same reason `host_overrides.patch_encrypted`
-- is, and more so. A report carries the check's output and perfdata, who ran it, its
-- arguments when the agent records them, and a whole metrics snapshot — several hundred
-- keys including the string metrics some modules publish: host names, OS versions,
-- interface names and addresses. The columns beside it are the ones a list needs, in the
-- clear so that listing a host's reports does not decrypt every one of them.

CREATE TABLE failure_contexts (
    id                 TEXT PRIMARY KEY,
    tenant_id          INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id            TEXT    NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,

    command            TEXT    NOT NULL,
    alias              TEXT    NOT NULL DEFAULT '',
    -- Nagios status number and the agent's own word for it, from the newest report.
    status             INTEGER NOT NULL,
    status_word        TEXT    NOT NULL,
    -- The check's own first line, for list views.
    message            TEXT    NOT NULL,
    -- Who ran it: `Scheduler`, `NRPEServer`, `WEBServer:admin`.
    subject            TEXT    NOT NULL DEFAULT '',

    -- What became of the metrics snapshot: captured | evicted | too_large | disabled | none.
    -- Not a CHECK constraint: it is the agent's vocabulary, and a newer agent that adds a
    -- state should not be refused by a server that has not been redeployed.
    context_state      TEXT    NOT NULL DEFAULT 'none',
    -- Metric keys in the stored snapshot, 0 when there is none.
    metrics_count      INTEGER NOT NULL DEFAULT 0,

    payload_encrypted  BLOB    NOT NULL,
    -- Plaintext size of the report.
    payload_bytes      INTEGER NOT NULL,

    -- When the newest report arrived.
    reported_at        INTEGER NOT NULL,

    -- The latest report replaces the previous one for the same check.
    UNIQUE (tenant_id, host_id, command, alias)
);

-- A host's reports, newest first: the host page, and picking the latest snapshot.
CREATE INDEX idx_failure_contexts_host_reported
    ON failure_contexts (tenant_id, host_id, reported_at DESC);
-- The retention sweep.
CREATE INDEX idx_failure_contexts_reported ON failure_contexts (reported_at);

-- Per-tenant settings: whether agents report at all, how often, and which model explains
-- errors.
--
-- One table rather than two because the two halves are one operator decision made on one
-- page, and because the first feeds the second: a tenant that takes no reports has no
-- snapshots to explain against (facts still arrive by their own route).
--
-- `reports_enabled` is what the desired-state handler turns into the `X-Failure-Context`
-- header. Switching it off stops the header, and an agent that stops seeing the header
-- stops posting — so a tenant can turn the traffic off from here without touching a host.
--
-- `explain_enabled` defaults to 0, and the absence of a row means reports are taken and
-- nothing is sent to a model. Nothing about a customer's hosts leaves this server until
-- someone has said where to.
CREATE TABLE tenant_failure_settings (
    tenant_id            INTEGER PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    reports_enabled      INTEGER NOT NULL DEFAULT 1,
    -- Seconds advertised as `min-interval`, or 0 to let the agent keep its own interval.
    -- A minimum, not an instruction: an agent configured for longer keeps the longer one.
    min_interval_secs    INTEGER NOT NULL DEFAULT 0,

    explain_enabled      INTEGER NOT NULL DEFAULT 0,
    -- 'anthropic' | 'openai' | 'ollama'. Not a CHECK constraint: the set of providers is
    -- code (see `fleet_server::llm`), a new one should not need a migration, and an
    -- unrecognised value fails loudly at the one place that resolves it.
    provider             TEXT    NOT NULL DEFAULT '',
    model                TEXT    NOT NULL DEFAULT '',
    -- Overrides the provider's default endpoint. This is what makes "various models" more
    -- than three: any OpenAI-compatible endpoint (Azure OpenAI, a vLLM or llama.cpp
    -- server, a gateway) is the 'openai' provider with a base_url, and a local Ollama is
    -- the same trick without a key.
    base_url             TEXT,
    api_key_encrypted    BLOB,
    -- Model calls this tenant may make per UTC day, 0 for none. Each explanation is a paid
    -- request, and an API key in a script can ask for them in a loop.
    daily_call_budget    INTEGER NOT NULL DEFAULT 200,

    updated_at           INTEGER NOT NULL,
    updated_by_user      INTEGER REFERENCES users(id)
);

-- What a tenant has actually spent, one row per UTC day.
--
-- Separate from the settings row so the budget check is a read of a small hot row, and so
-- the history survives a settings change.
CREATE TABLE llm_usage (
    tenant_id      INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- UTC day as days-since-epoch, so "today" is one integer and no string parsing.
    day            INTEGER NOT NULL,
    calls          INTEGER NOT NULL DEFAULT 0,
    failures       INTEGER NOT NULL DEFAULT 0,
    input_tokens   INTEGER NOT NULL DEFAULT 0,
    output_tokens  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, day)
);
