-- 0015_alert_contexts.sql
--
-- Storage for the context an agent sends when a check goes WARNING or CRITICAL, and for
-- the description a language model writes from it.
--
-- 0005 dropped metrics with the note that a fleet *config* control plane does not need a
-- time-series store. That still holds, and this table is deliberately not one. The
-- difference is the grain: metrics stored one row per sample per host per interval, forever
-- — a series. This stores **one row per distinct problem per host**, which is a set whose
-- size is bounded by how many things are broken, not by how long they have been broken or
-- how often the agent looks.
--
-- That is what `fingerprint` buys, and it is the single most important thing about this
-- schema. A check runs on a timer; a full disk is still full on the next pass. The agent
-- posts an alert every time, and the UNIQUE constraint below turns the repeats into an
-- `occurrences` bump and a new `last_seen_at` on the row that is already there. A host with
-- one broken check writes one row whether it reports for an hour or a month, and the model
-- is asked to describe that problem once rather than once a minute. Without it, "report
-- context on every check execution" would be a write per check per interval per host —
-- precisely the shape 0005 removed, arriving through a different door.
--
-- Two cheap properties fall out of the same constraint: the enrichment worker's unit of
-- work is a problem rather than an occurrence, so its cost is bounded by the same set; and
-- a flapping check cannot outrun retention, because it keeps rewriting one row.
--
-- `payload_encrypted` is a ciphertext for the same reason `host_overrides.patch_encrypted`
-- is. The document holds paths, process tables, service names and log lines lifted off a
-- customer's machine — if anything in this database deserves the master key, it is this.
-- The columns beside it (command, alias, status, message) are the ones a list view and the
-- worker's queue scan need, and are stored in the clear so that neither has to decrypt
-- every row to render a page or pick up a job.

CREATE TABLE alert_contexts (
    id                 TEXT PRIMARY KEY,
    tenant_id          INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    host_id            TEXT    NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,

    -- sha256 of (command, arguments, status) — see fleet_core::alert::AlertContext::fingerprint.
    fingerprint        TEXT    NOT NULL,

    command            TEXT    NOT NULL,
    alias              TEXT,
    status             TEXT    NOT NULL CHECK (status IN ('warning', 'critical')),
    -- The first detail line, for list views. Denormalised out of the payload so the hosts
    -- and alerts pages never decrypt anything.
    message            TEXT    NOT NULL,

    payload_encrypted  BLOB    NOT NULL,
    -- Plaintext size of the document. The ciphertext length is visible anyway; having the
    -- number as a column is what lets a per-tenant byte budget be enforced with a SUM
    -- instead of a table scan and a decrypt.
    payload_bytes      INTEGER NOT NULL,

    occurrences        INTEGER NOT NULL DEFAULT 1,
    first_seen_at      INTEGER NOT NULL,
    last_seen_at       INTEGER NOT NULL,

    -- Enrichment state machine. 'pending' is the only state the worker picks up:
    --
    --   pending  → nothing has described this yet (a fresh row, or one whose payload
    --              changed enough to be worth re-describing, or an operator re-run)
    --   done     → enrichment_* below are populated
    --   failed   → attempts exhausted; enrichment_error says why. Terminal until an
    --              operator asks again, so a provider outage cannot turn into an
    --              indefinite retry loop against someone's paid API
    --   skipped  → the tenant has enrichment switched off, or has spent its budget. Not
    --              an error, and distinguished from 'failed' precisely so the UI can say
    --              "not enabled" rather than "something went wrong"
    enrichment_state   TEXT    NOT NULL DEFAULT 'pending'
                       CHECK (enrichment_state IN ('pending', 'done', 'failed', 'skipped')),
    enrichment_attempts        INTEGER NOT NULL DEFAULT 0,
    -- Backoff gate. NULL means eligible now.
    enrichment_next_attempt_at INTEGER,
    enrichment_error           TEXT,
    enrichment_provider        TEXT,
    enrichment_model           TEXT,
    -- The model's answer, encrypted under the same purpose as the payload: it is a
    -- restatement of the same evidence and is no less sensitive than its input.
    enrichment_encrypted       BLOB,
    enriched_at                INTEGER,
    enrichment_input_tokens    INTEGER,
    enrichment_output_tokens   INTEGER,

    -- The coalescing rule itself.
    UNIQUE (tenant_id, host_id, fingerprint)
);

-- The tenant-wide alerts page, newest first.
CREATE INDEX idx_alert_contexts_tenant_seen ON alert_contexts (tenant_id, last_seen_at DESC);
-- One host's alerts, on the host detail page. Distinct from the index above because a host
-- with ten alerts inside a tenant with fifty thousand should cost ten rows to render.
CREATE INDEX idx_alert_contexts_host_seen ON alert_contexts (tenant_id, host_id, last_seen_at DESC);
-- The worker's queue scan. Leading with the state keeps it off the rows it can never
-- claim, which after a steady-state period is very nearly all of them.
CREATE INDEX idx_alert_contexts_pending ON alert_contexts (enrichment_state, enrichment_next_attempt_at);

-- Per-tenant model-provider configuration.
--
-- A row per tenant rather than a process-wide setting, because the two deployments this
-- serves want opposite things: an on-prem install has one tenant and an operator who is
-- happy to set environment variables, while a hosted install has many tenants who do not
-- share an API key, a provider, a model, or a view on whether their operational data may
-- be sent to a third party at all. The environment variables remain the default (see
-- `LlmConfig::from_env`); a row here overrides them for that tenant.
--
-- `enabled` defaults to 0, and the absence of a row means disabled. Nothing about a check
-- result leaves this server until someone has said it may: an alert that arrives with no
-- configuration is stored and marked 'skipped', not sent somewhere by default.
CREATE TABLE tenant_llm_settings (
    tenant_id          INTEGER PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    enabled            INTEGER NOT NULL DEFAULT 0,
    -- 'anthropic' | 'openai' | 'ollama'. Not a CHECK constraint: the set of providers is
    -- code (see `fleet_server::llm`), a new one should not need a migration, and an
    -- unrecognised value fails loudly at the one place that resolves it.
    provider           TEXT    NOT NULL,
    model              TEXT    NOT NULL,
    -- Overrides the provider's default endpoint. This is what makes "various LLMs" more
    -- than three: any OpenAI-compatible endpoint (Azure OpenAI, a vLLM or llama.cpp
    -- server, a gateway) is the 'openai' provider with a base_url, and a local Ollama is
    -- the same trick without a key.
    base_url           TEXT,
    api_key_encrypted  BLOB,
    -- Model calls this tenant may make per UTC day, 0 for none. The cap that matters: a
    -- fleet whose checks are all failing produces new fingerprints faster than anyone
    -- watches, and each one is a paid request.
    daily_call_budget  INTEGER NOT NULL DEFAULT 200,
    updated_at         INTEGER NOT NULL,
    updated_by_user    INTEGER REFERENCES users(id)
);

-- What a tenant has actually spent, one row per UTC day.
--
-- Separate from the settings row so the budget check is a read of a small hot row rather
-- than an aggregate over alert_contexts, and so the history survives a settings change.
-- Swept by housekeeping like everything else here.
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
