# LLM enrichment of failure contexts

When a check fails on a monitored host, the agent can report it together with the metrics
snapshot it held at that moment (see
[agent-integration.md §4](agent-integration.md#4-failure-context)). This page is about what
the server then does with it: hand it to a language model and ask for a plain-language
description, so whoever picks up the failure starts from an explanation rather than from
`CRITICAL: 5m: 97%`.

Two switches, and they are independent:

| switch | default | what it controls |
|---|---|---|
| `reports_enabled` | **on** | whether this server advertises `X-Failure-Context` and so whether agents report at all |
| `enrichment_enabled` | **off** | whether a stored report is sent to a model |

So the default install collects failures and sends nothing anywhere. Nothing about a
monitored host leaves this server until somebody configures a provider.

---

## 1. Choosing a provider

Three, chosen to cover the deployments rather than to enumerate vendors.

| provider | endpoint | key | what it is for |
|---|---|---|---|
| `anthropic` | `POST {base}/v1/messages` | required | The Claude API. Default base `https://api.anthropic.com`, default model `claude-opus-5`. |
| `openai` | `POST {base}/chat/completions` | required | OpenAI **and anything that speaks its Chat Completions shape** — Azure OpenAI, vLLM, llama.cpp's server, Groq, Together, an in-house gateway. Point `base_url` at it. |
| `ollama` | `POST {base}/api/chat` | not required | A local Ollama daemon. Default base `http://127.0.0.1:11434`. No egress, no credential, no third party. |

The `openai` provider does most of the work of the phrase "various models": Chat Completions
is the de-facto interchange format, so a `base_url` is usually all it takes to put a model of
your choosing behind this. `azure` and `openai-compatible` are accepted as aliases.

All three are asked for **schema-constrained output**, because the answer is rendered as
fields in the console and "mostly JSON with a sentence of preamble" is a parse failure. A
server that ignores the request and wraps its answer in a fence is still handled — the answer
is recovered — but a genuinely unconstrained model will fail more often.

Adding a fourth is a file in `crates/server/src/llm/` and a match arm; the stored `provider`
column deliberately has no `CHECK` constraint, so it does not need a migration.

---

## 2. Configuring it

### Per tenant, from the console

`PUT /api/failures/settings`. Requires a role that can change configuration.

```json
{
  "reports_enabled": true,
  "min_interval_secs": 0,
  "enrichment_enabled": true,
  "provider": "anthropic",
  "model": "claude-opus-5",
  "base_url": null,
  "api_key": "sk-ant-...",
  "daily_call_budget": 200
}
```

- `api_key` is **write-only**. `GET /api/failures/settings` reports `api_key_set: true` and
  never the key — not to an admin, not to a platform admin. Omit the field to keep the stored
  key when changing anything else; send `""` to clear it.
- Settings that cannot work are refused when you save them, not one report at a time: an
  unknown provider, a `base_url` that is not an http(s) URL, an empty model, or enabling a
  key-requiring provider with no key. The provider and model are only validated when
  `enrichment_enabled` is true — switching it off should not require a valid provider.
- Enabling enrichment re-queues everything that arrived while it was off. Reports whose check
  *passed* stay parked: enabling enrichment is not a reason to describe a success.
- `min_interval_secs` is advertised to agents as a floor on their own reporting interval,
  never a ceiling. Maximum a week.
- Turning either switch on or off is written to the audit log, with the provider and model.

### Process-wide, from the environment

The on-prem path: one tenant, an operator with a shell. A tenant with no settings row of its
own falls back to this.

| var | default | notes |
|---|---|---|
| `LLM_PROVIDER` | unset | `anthropic`, `openai` or `ollama`. Unset means no server-wide default. |
| `LLM_MODEL` | provider's default | |
| `LLM_API_KEY` | | Required unless the provider is `ollama`. |
| `LLM_BASE_URL` | provider's default | The override that makes any compatible endpoint work. |
| `LLM_DAILY_CALL_BUDGET` | unlimited | Per tenant, per UTC day. Unlimited on this path is deliberate — you are paying your own bill or running your own model. |

A half-configuration (`LLM_PROVIDER` set, `LLM_API_KEY` missing) or an unrecognised provider
**fails startup**. A typo here would otherwise show up as descriptions that silently never
arrive, which is far worse to debug than a failed boot.

Air-gapped, in full:

```bash
LLM_PROVIDER=ollama
LLM_MODEL=llama3.1
LLM_BASE_URL=http://10.0.0.5:11434
```

---

## 3. What it costs, and what bounds it

A model call is the only thing this server does that costs money per unit, so the bounds
matter more than the feature.

**The agent paces itself.** At most one report per host per interval (default an hour),
whatever is failing, with the rest of the window summarised inside it. A host with forty
broken checks sends the same one report as a host with one.

**One description per problem, not per report.** A row is identified by
`(command, alias, status, arguments)`; a check failing every hour for a week is one row with
`occurrences` in the hundreds, described **once**. A check crossing from `warning` to
`critical` is a different problem and gets its own description, which is the behaviour you
want.

**A daily call budget per tenant.** Default 200/day. Every attempt counts against it,
successful or not: a request that fails after the provider read the prompt has usually been
billed. Reports past the budget are marked `skipped` with a message saying so, and the next
day resumes. `GET /api/failures/settings` reports `calls_today` and `failures_today` — the
second is what a misconfiguration looks like from outside.

**The snapshot is bounded in the prompt.** A snapshot is several hundred keys; the prompt
takes them up to ~12 KB of rendered text and then says how many it left out, so a model that
saw a subset can qualify its answer instead of speaking as though it saw everything.

**Three attempts, then stop.** Failures are split into retryable (a timeout, a 429, a 5xx, an
answer that did not parse) and terminal (401/403, 400, an unknown model, a refusal). A
terminal failure gives up on the first attempt: re-sending identical bytes to an endpoint that
revoked your key is not a retry strategy. Retryable failures back off one minute, five,
twenty-five, then stop. `POST /api/failures/{id}/describe` re-queues a row once the cause is
fixed.

**Effort is set low.** Describing a failed check is a short, well-specified, high-volume task
— the kind that does not repay deep reasoning. The lever is effort rather than a smaller
model: you keep the judgement of the model you chose at a fraction of the thinking spend.

Retention: rows are dropped 30 days after they were last reported, and a host keeps at most
200 distinct problems on file.

---

## 4. Privacy and prompt-injection posture

The part to read before enabling this on a tenant whose data you do not own.

**Consent is the defence that carries the weight.** Enrichment is off until someone turns it
on, per tenant, and the `ollama` provider exists so that "this data does not leave our
network" is a configuration rather than a reason to do without the feature.

**A snapshot is more than numbers.** It carries the string metrics modules publish — host
names, OS and version strings, interface names and addresses, service names. Worth knowing
before sending one to a third party; it is also why the report is encrypted at rest.

**Obvious credentials are stripped before the prompt is built.** Check arguments carry
`--password=`, output lines carry tokens, and a service name can carry anything.
`crates/server/src/llm/redact.rs` masks secret-looking `key=value` and `key: value` pairs and
whole PEM private-key blocks. It is a coarse net over the shapes that recur, **not a
guarantee** — a secret that does not look like one gets through.

**The evidence is data, never instruction.** Everything in a report was written by software on
a machine we do not control, and anyone who can name a service on a monitored host can write
text into a metrics snapshot. So:

- the task is in the system prompt; the evidence is in the user message, fenced and
  introduced as untrusted data;
- the fence markers are neutralised if they appear inside the evidence, so a payload cannot
  close its own block and have what follows read as our instructions;
- the model gets **no tools, no network and no write path**. The worst a successful injection
  achieves is a misleading paragraph in a panel labelled as model-written;
- the answer is parsed against a schema, clamped, and rendered as text. It never becomes a
  command, a query, or a field anything dispatches on.

**At rest, both the report and the description are encrypted** under the master key, bound to
the tenant and host they belong to. A row moved onto another host fails to decrypt rather than
being served — or described — as that host's evidence.

**Nothing sensitive is logged.** The worker logs the provider, model and token counts; it does
not log the description, which restates a customer's host state.

---

## 5. Reading the result

`GET /api/failures` (optionally `?host_id=` / `?status=` / `?limit=`) and
`GET /api/failures/{id}`, which adds the report verbatim. The description, where one exists:

```json
{
  "summary": "The system drive on web01 is essentially full...",
  "likely_causes": ["IIS logs in C:\\inetpub\\logs have not been rotated"],
  "suggested_checks": ["Check the age of files under C:\\inetpub\\logs"],
  "severity_assessment": "important",
  "confidence": "high"
}
```

`severity_assessment` is the model's read of the evidence, deliberately separate from the
check's own status — a check can be CRITICAL about something routine, and the point of the
description is to say so. `confidence` is worth surfacing next to the summary: a `low` here
usually means the report arrived without a snapshot, and the fix is on the agent side
(`capture metrics = true` under `[/settings/core/failed checks]`).

`enrichment_state` says where a row stands:

| state | meaning |
|---|---|
| `pending` | queued, or waiting out a backoff |
| `done` | `description` is populated |
| `failed` | attempts exhausted; `enrichment_error` says why. Re-run with `POST /api/failures/{id}/describe` |
| `skipped` | not enabled for this tenant, the day's budget is spent, or the check passed. Not an error |

The list also carries `context_state` (whether a snapshot came with the report, and if not
why), `metrics_count`, and `window_suppressed` / `window_evicted` from the newest report's
window — the latter two are that window's, not running totals, because the agent groups its
summary across every check and summing it onto one problem would misattribute.
