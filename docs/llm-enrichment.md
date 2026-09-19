# LLM enrichment of alert contexts

When a check on a monitored host goes WARNING or CRITICAL, the agent can post what it saw —
the check result, its measurements, and the output of whatever context commands the operator
attached to it (see [agent-integration.md §4](agent-integration.md#4-alert-context)). This
page is about what the server then does with it: hand it to a language model and ask for a
plain-language description of the problem, so that whoever picks up the alert starts from an
explanation rather than from `CRITICAL: C:\ used 95.2% > 90%`.

It is **off by default** and stays off until somebody configures a provider. Nothing about a
monitored host leaves this server before that.

---

## 1. Choosing a provider

There are three, chosen to cover the deployments rather than to enumerate vendors.

| provider | endpoint | key | what it is for |
|---|---|---|---|
| `anthropic` | `POST {base}/v1/messages` | required | The Claude API. Default base `https://api.anthropic.com`, default model `claude-opus-5`. |
| `openai` | `POST {base}/chat/completions` | required | OpenAI **and anything that speaks its Chat Completions shape** — Azure OpenAI, vLLM, llama.cpp's server, Groq, Together, an in-house gateway. Point `base_url` at it. |
| `ollama` | `POST {base}/api/chat` | not required | A local Ollama daemon. Default base `http://127.0.0.1:11434`. No egress, no credential, no third party. |

The `openai` provider is the one doing most of the work of the phrase "various LLMs": Chat
Completions is the de-facto interchange format, so a `base_url` is usually all it takes to
put a model of your choosing behind this. `azure` and `openai-compatible` are accepted as
aliases for it.

All three are asked for **schema-constrained output**, because the answer is rendered as
fields in the console and "mostly JSON with a sentence of preamble" is a parse failure. A
server that ignores the request and wraps its answer in a fence is still handled — the
answer is recovered — but a genuinely unconstrained model will fail more often.

Adding a fourth provider is a file in `crates/server/src/llm/` and a match arm; the stored
`provider` column deliberately has no `CHECK` constraint, so it does not need a migration.

---

## 2. Configuring it

### Per tenant, from the console

`PUT /api/alerts/settings`, or the console's equivalent. Requires a role that can change
configuration.

```json
{
  "enabled": true,
  "provider": "anthropic",
  "model": "claude-opus-5",
  "base_url": null,
  "api_key": "sk-ant-...",
  "daily_call_budget": 200
}
```

- `api_key` is **write-only**. `GET /api/alerts/settings` reports `api_key_set: true` and
  never the key itself — not to an admin, not to a platform admin. Omit the field to keep
  the stored key when changing anything else; send `""` to clear it.
- A configuration that cannot work is refused when you save it, not one alert at a time: an
  unknown provider, a `base_url` that is not an http(s) URL, an empty model, or enabling a
  key-requiring provider with no key.
- Enabling it re-queues everything that arrived while it was off — those are exactly the
  alerts you now want described.
- Turning it on or off is written to the audit log, with the provider and model.

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

**One description per problem, not per check run.** This is the important one. The store
identifies a problem by `(command, arguments, status)`; a check failing every minute for a
week is one row with `occurrences` in the thousands, described **once**. A disk that stays
full does not bill you every minute. A check that crosses from `warning` to `critical` is a
different problem and gets its own description, which is the behaviour you want.

**A daily call budget per tenant.** Default 200/day. Every attempt counts against it,
successful or not: a request that fails after the provider read the prompt has usually been
billed. Alerts past the budget are marked `skipped` with a message saying so, and the next
day resumes. `GET /api/alerts/settings` reports `calls_today` and `failures_today` — the
second is what a misconfiguration looks like from the outside.

**Three attempts, then stop.** Failures are classified into retryable (a timeout, a 429, a
5xx, an answer that did not parse) and terminal (401/403, 400, an unknown model, a refusal).
A terminal failure gives up on the first attempt: re-sending identical bytes to an endpoint
that has revoked your key is not a retry strategy. Retryable failures back off one minute,
five, twenty-five, then stop. `POST /api/alerts/:id/describe` re-queues a row once the cause
is fixed.

**Effort is set low.** Describing a monitoring alert is a short, well-specified, high-volume
task, which is the kind that does not repay deep reasoning. The lever is effort rather than
a smaller model: you keep the judgement of the model you chose at a fraction of the thinking
spend.

Retention: alerts are dropped 30 days after they were last seen, and a host keeps at most
200 distinct problems on file.

---

## 4. Privacy and prompt-injection posture

This is the part to read before enabling it on a tenant whose data you do not own.

**Consent is the defence that carries the weight.** Enrichment is off until someone turns it
on, per tenant, and the `ollama` provider exists so that "this data does not leave our
network" is a configuration rather than a reason to do without the feature.

**Obvious credentials are stripped before the prompt is built.** Alert evidence is collected
by running commands on a host, and those commands print credentials: a process table carries
`--password`, a config check prints an INI file, a failing service logs the token it tried.
`crates/server/src/llm/redact.rs` masks secret-looking `key=value` and `key: value` pairs and
whole PEM private-key blocks. It is a coarse net over the shapes that recur, **not a
guarantee** — a secret that does not look like one gets through.

**The evidence is data, never instruction.** Everything in an alert context was written by
software on a machine we do not control, and anyone who can name a process on a monitored
host can write text into a process table. So:

- the task is in the system prompt; the evidence is in the user message, fenced and
  introduced as untrusted data;
- the fence markers are neutralised if they appear inside the evidence, so a payload cannot
  close its own block and have what follows read as our instructions;
- the model gets **no tools, no network and no write path**. The worst a successful
  injection achieves is a misleading paragraph in a panel labelled as model-written;
- the answer is parsed against a schema, clamped, and rendered as text. It never becomes a
  command, a query, or a field anything dispatches on.

**At rest, both the evidence and the description are encrypted** under the server's master
key, bound to the tenant and host they belong to — the same treatment host configuration
overrides get. A row moved onto another host fails to decrypt rather than being served as
that host's evidence.

**Nothing sensitive is logged.** The worker logs the provider, model and token counts; it
does not log the description, which is a restatement of a customer's host state.

---

## 5. Reading the result

`GET /api/alerts` (optionally `?host_id=` / `?status=` / `?limit=`) and
`GET /api/alerts/:id`. The description, where one exists:

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
usually means the alert arrived with no `context` items, and the fix is on the agent side.

`enrichment_state` says where a row stands:

| state | meaning |
|---|---|
| `pending` | queued, or waiting out a backoff |
| `done` | `description` is populated |
| `failed` | attempts exhausted; `enrichment_error` says why. Re-run with `POST /api/alerts/:id/describe` |
| `skipped` | not enabled for this tenant, or the day's budget is spent. Not an error |
