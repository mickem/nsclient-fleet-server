-- 0017_failure_contexts.sql
--
-- Storage for the failure-context reports an enrolled agent sends (NSClient++
-- `POST /agent/v1/failure-context`), and for the description a language model writes from
-- one.
--
-- 0005 dropped metrics with the note that a fleet *config* control plane does not need a
-- time-series store. That still holds, and this is not one. Two things keep it from becoming
-- one, and they are the whole design:
--
--   * **The agent paces itself.** It sends at most one report per host per interval
--     (default an hour), whatever is failing, and summarises every other failure in that
--     window inside the report. So the arrival rate is set by the interval and the fleet
--     size, not by how badly the fleet is doing — a host with forty broken checks sends
--     the same one report as a host with one.
--   * **A row is a problem, not a report.** `fingerprint` hashes
--     (command, alias, status, arguments) and the UNIQUE below collapses a repeat onto the
--     row already there: newest payload, `last_seen_at` moved, `occurrences` incremented.
--     A disk that stays full for a week is one row, not 168.
--
-- Together those bound the table by *distinct problems in the fleet*, which is a set that
-- changes at human speed. They also bound what enrichment costs: the unit of work is a
-- problem, so the model is asked once per problem rather than once per report.
--
-- `payload_encrypted` is a ciphertext for the same reason `host_overrides.patch_encrypted`
-- is, and more so. A report carries the check's output and perfdata, who ran it, its
-- arguments when the agent records them, and a whole metrics snapshot — several hundred
-- keys including the string metrics some modules publish: host names, OS versions,
-- interface names and addresses. If anything in this database deserves the master key, it
-- is this. The columns beside it are the ones a list view and the enrichment queue need,
-- and are in the clear so that neither has to decrypt every row to do its job.

CREATE TABLE failure_contexts (
    id                 TEXT PRIMARY KEY,
    tenant_id          INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id            TEXT    NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,

    -- sha256 of (command, alias, status, arguments) — see
    -- fleet_core::failures::FailedCheck::fingerprint.
    fingerprint        TEXT    NOT NULL,

    command            TEXT    NOT NULL,
    alias              TEXT    NOT NULL DEFAULT '',
    -- Nagios status number and the agent's own word for it. Both, because the number is
    -- what filters and the word is what renders — and the agent sends both.
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
    -- Metric keys in the stored snapshot, 0 when there is none. Lets a list say "521
    -- metrics" and the enrichment worker judge a prompt's size without a decrypt.
    metrics_count      INTEGER NOT NULL DEFAULT 0,

    -- From the newest report's `suppressed` block: how many other failures the agent saw in
    -- that window, and how many its own log cap dropped before they could be reported.
    -- Deliberately the latest window rather than a running total: the agent groups by
    -- (command, status) across every check, so summing it onto one fingerprint's row would
    -- attribute other checks' failures to this problem.
    window_suppressed  INTEGER NOT NULL DEFAULT 0,
    window_evicted     INTEGER NOT NULL DEFAULT 0,

    payload_encrypted  BLOB    NOT NULL,
    -- Plaintext size of the report. The ciphertext length is visible anyway; having the
    -- number as a column is what lets a size budget be a SUM rather than a scan and a
    -- decrypt.
    payload_bytes      INTEGER NOT NULL,

    -- Reports that collapsed onto this row.
    occurrences        INTEGER NOT NULL DEFAULT 1,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL,

    -- Enrichment state machine. 'pending' is the only state the worker picks up:
    --
    --   pending  → nothing has described this yet (a fresh row, or an operator re-run)
    --   done     → enrichment_* below are populated
    --   failed   → attempts exhausted; enrichment_error says why. Terminal until an
    --              operator asks again, so a provider outage cannot become an indefinite
    --              retry loop against someone's paid API
    --   skipped  → the tenant has enrichment off, has spent its budget, or the report is
    --              not a failure at all. Not an error, and kept distinct from 'failed' so
    --              the UI can say "not enabled" rather than "something went wrong"
    enrichment_state   TEXT    NOT NULL DEFAULT 'pending'
                       CHECK (enrichment_state IN ('pending', 'done', 'failed', 'skipped')),
    enrichment_attempts        INTEGER NOT NULL DEFAULT 0,
    -- Backoff gate. NULL means eligible now.
    enrichment_next_attempt_at INTEGER,
    enrichment_error           TEXT,
    enrichment_provider        TEXT,
    enrichment_model           TEXT,
    -- The model's answer, encrypted under the same purpose as the payload: it restates the
    -- same evidence and is no less sensitive than its input.
    enrichment_encrypted       BLOB,
    enriched_at                INTEGER,
    enrichment_input_tokens    INTEGER,
    enrichment_output_tokens   INTEGER,

    -- The coalescing rule itself.
    UNIQUE (tenant_id, host_id, fingerprint)
);

-- The tenant-wide failures page, newest first.
CREATE INDEX idx_failure_contexts_tenant_seen ON failure_contexts (tenant_id, last_seen_at DESC);
-- One host's failures, on the host detail page. Distinct from the index above because a
-- host with ten failures inside a tenant with fifty thousand should cost ten rows to render.
CREATE INDEX idx_failure_contexts_host_seen ON failure_contexts (tenant_id, host_id, last_seen_at DESC);
-- The worker's queue scan. Leading with the state keeps it off the rows it can never claim,
-- which in a steady state is very nearly all of them.
CREATE INDEX idx_failure_contexts_pending ON failure_contexts (enrichment_state, enrichment_next_attempt_at);

-- Per-tenant settings for the feature: whether to take reports at all, how often, and which
-- model describes them.
--
-- One table rather than two because the two halves are one operator decision made on one
-- page, and because the first of them gates the second: a tenant that takes no reports has
-- nothing to enrich.
--
-- `reports_enabled` is what the desired-state handler turns into the `X-Failure-Context`
-- header. Switching it off stops the header, and an agent that stops seeing the header
-- stops posting — so a tenant can turn the traffic off from here without touching a host.
--
-- `enrichment_enabled` defaults to 0, and the absence of a row means reports are taken and
-- nothing is sent to a model. Nothing about a customer's hosts leaves this server until
-- someone has said where to.
CREATE TABLE tenant_failure_settings (
    tenant_id            INTEGER PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,

    reports_enabled      INTEGER NOT NULL DEFAULT 1,
    -- Seconds advertised as `min-interval`, or 0 to let the agent keep its own interval.
    -- A minimum, not an instruction: an agent configured for longer keeps the longer one.
    min_interval_secs    INTEGER NOT NULL DEFAULT 0,

    enrichment_enabled   INTEGER NOT NULL DEFAULT 0,
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
    -- Model calls this tenant may make per UTC day, 0 for none. The cap that matters: a
    -- fleet whose checks are all failing produces new fingerprints faster than anyone
    -- watches, and each one is a paid request.
    daily_call_budget    INTEGER NOT NULL DEFAULT 200,

    updated_at           INTEGER NOT NULL,
    updated_by_user      INTEGER REFERENCES users(id)
);

-- What a tenant has actually spent, one row per UTC day.
--
-- Separate from the settings row so the budget check is a read of a small hot row rather
-- than an aggregate over failure_contexts, and so the history survives a settings change.
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
