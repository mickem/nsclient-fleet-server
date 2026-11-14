# Explaining errors

This server is not a monitoring system. Your monitoring system raises the alert, decides how
serious it is and tracks how long it stays open. What the fleet adds is **context**: when
someone holding an error asks *why*, the fleet has the host's latest metrics snapshot, its
inventory facts, and the agent's own record of the check that failed. This page is about
handing an error and that evidence to a language model and getting an explanation back.

There are two ways to ask:

- **The console.** Open the host, go to its **Context** tab, paste the error, press Explain.
- **The API**, for scripts and for `check_nsclient fleet explain`: `POST /api/explain`
  (§5).

The model explains the error. It does **not** judge how severe it is or review the host's
health in general — that is the monitoring system's call, and a second opinion on it from a
model would only be noise.

The evidence comes from two places:

- **Failure reports.** When a check fails, the agent can report it with the metrics snapshot
  it held at that moment (see [agent-integration.md §4](agent-integration.md#4-failure-context)).
  The server keeps the latest report per check per host.
- **Facts.** The host's inventory — OS, hardware, volumes, interfaces, software — as the agent
  uploads it, plus any imported facts sources (see
  [agent-integration.md §3](agent-integration.md#3-host-facts-inventory)).

Two switches, and they are independent:

| switch | default | what it controls |
|---|---|---|
| `reports_enabled` | **on** | whether this server advertises `X-Failure-Context`, and so whether agents report at all |
| `explain_enabled` | **off** | whether errors can be sent to a model for explanation |

So the default install collects evidence and sends nothing anywhere. Nothing about a
monitored host leaves this server until somebody configures a provider.

---

## 1. Choosing a provider

Three, chosen to cover the deployments rather than to enumerate vendors.

| provider | endpoint | key | what it is for |
|---|---|---|---|
| `anthropic` | `POST {base}/v1/messages` | required | The Claude API. Default base `https://api.anthropic.com`, default model `claude-haiku-5-5`. |
| `openai` | `POST {base}/chat/completions` | required | OpenAI **and anything that speaks its Chat Completions shape** — Azure OpenAI, vLLM, llama.cpp's server, Groq, Together, an in-house gateway. Point `base_url` at it. |
| `ollama` | `POST {base}/api/chat` | not required | A local Ollama daemon. Default base `http://127.0.0.1:11434`. No egress, no credential, no third party. |

The `openai` provider does most of the work of the phrase "various models": Chat Completions
is the de-facto interchange format, so a `base_url` is usually all it takes to put a model of
your choosing behind this. `azure` and `openai-compatible` are accepted as aliases.

All three are asked for **schema-constrained output**, because the answer is rendered as
fields and "mostly JSON with a sentence of preamble" is a parse failure. A server that
ignores the request and wraps its answer in a fence is still handled — the answer is
recovered — but a genuinely unconstrained model will fail more often.

Adding a fourth is a file in `crates/server/src/llm/` and a match arm; the stored `provider`
column deliberately has no `CHECK` constraint, so it does not need a migration.

---

## 2. Configuring it

### Per tenant, from the console

**Settings** in the sidebar, or `PUT /api/settings/explain`. Every role can read the
settings; changing them requires a role that can change configuration.

```json
{
  "reports_enabled": true,
  "min_interval_secs": 0,
  "explain_enabled": true,
  "provider": "anthropic",
  "model": "claude-haiku-5-5",
  "base_url": null,
  "api_key": "sk-ant-...",
  "daily_call_budget": 200
}
```

- The console's Model field suggests models for the chosen provider, its default first: for
  `anthropic`, `claude-haiku-5-5` (the default), `claude-sonnet-5-5` and `claude-opus-5-5`;
  for the other two, their default. Any other name the provider serves can be typed in.
  `GET /api/settings/explain` returns the list as `suggested_models`.
- `api_key` is **write-only**. `GET /api/settings/explain` reports `api_key_set: true` and
  never the key — not to an admin, not to a platform admin. Omit the field to keep the stored
  key when changing anything else; send `""` to clear it.
- A stored key stays with the provider and base URL it was given for. Changing either
  without sending the key again is refused: a key nobody can read back must not be one
  somebody can have delivered to an endpoint of their choosing. Enter the key again, or
  clear it. A trailing slash, or spelling out the provider's default URL, is not a change.
- With `explain_enabled` false, the stored provider and base URL are kept as they are and
  the ones in the request are ignored, so switching explanations off and on again returns
  to the endpoint that was configured.
- Settings that cannot work are refused when you save them, not one explanation at a time:
  an unknown provider, a `base_url` that is not an http(s) URL, an empty model, or enabling a
  key-requiring provider with no key. The provider and model are only validated when
  `explain_enabled` is true — switching it off should not require a valid provider.
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

| `LLM_ALLOW_PRIVATE_ENDPOINTS` | off (on with `ON_PREM`) | Lets a *tenant's* settings name an endpoint on a private address. See below. |

A half-configuration (`LLM_PROVIDER` set, `LLM_API_KEY` missing) or an unrecognised provider
**fails startup**. A typo here would otherwise show up as every explanation failing, which is
far worse to debug than a failed boot.

### Where a tenant's endpoint may point

A tenant's `base_url` is a URL this server calls on that tenant's say-so, and the provider's
answer comes back to whoever asked. On a server shared by several tenants, an address inside
the server's own network — loopback, a private range, the cloud metadata address — would be a
request forged from inside. So an endpoint configured **by a tenant** has to be on the public
internet:

- a literal private address is refused when the settings are saved, and again when an
  explanation is asked for (`409`), however it is spelled (`http://2130706433/` is loopback);
- a name is checked as it is resolved, so one that resolves to a private address is not
  connected to;
- `ollama` with no `base_url` is the server's own loopback and is refused the same way;
- redirects are not followed, on any path. A model API has no reason to send one.

Two things lift this, both the server operator's to decide: `ON_PREM=1`, where one
organisation runs the server and a model on its own network is the point, and
`LLM_ALLOW_PRIVATE_ENDPOINTS=1` for a shared install whose tenants are trusted with the
network it sits on. The `LLM_*` default above is never restricted — whoever sets the
environment already has a shell on the machine. Calls to a tenant-configured endpoint on a
restricted server also ignore `HTTP(S)_PROXY`: through a proxy it is the proxy that resolves
the name, and the check would be made against the wrong address.

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

**Nothing runs in the background.** A model is called only when someone asks for an error to
be explained, and the answer goes back to them rather than into the database. A fleet with a
thousand failing checks costs nothing until someone asks about one.

**A daily call budget per tenant.** Default 200/day. Every attempt counts against it,
successful or not: a request that fails after the provider read the prompt has usually been
billed. Past the budget, `POST /api/explain` answers `429` until midnight UTC. This matters
because the route can be driven by an API key in a script. `GET /api/settings/explain`
reports `calls_today` and `failures_today` — the second is what a misconfiguration looks like
from outside.

**The evidence is bounded in the prompt.** A snapshot is several hundred keys; the prompt
takes them up to ~12 KB of rendered text, and facts up to ~8 KB across every source (the
agent's own first), and then says how much it left out — so a model that saw a subset can
qualify its answer instead of speaking as though it saw everything.

**No retries.** A failed call is reported to whoever asked (`502`, with the provider's reason)
and counted. Asking again is their decision: a revoked key or an unknown model fails the same
way every time, and an outage is something a person can see and wait out.

**Effort is set low.** Explaining one error against a page of evidence is a short,
well-specified task — the kind that does not repay deep reasoning. The lever is effort rather
than a smaller model: you keep the judgement of the model you chose at a fraction of the
thinking spend.

---

## 4. Privacy and prompt-injection posture

The part to read before enabling this on a tenant whose data you do not own.

**Consent is the defence that carries the weight.** Explanations are off until someone turns
them on, per tenant, and the `ollama` provider exists so that "this data does not leave our
network" is a configuration rather than a reason to do without the feature.

**A snapshot and an inventory are more than numbers.** The snapshot carries the string
metrics modules publish — host names, OS and version strings, interface names and addresses,
service names — and the facts carry the machine's whole inventory. Worth knowing before
sending them to a third party; it is also why reports are encrypted at rest.

**Obvious credentials are stripped before the prompt is built.** Check arguments carry
`--password=`, output lines carry tokens, and a service name can carry anything.
`crates/server/src/llm/redact.rs` masks secret-looking `key=value` and `key: value` pairs and
whole PEM private-key blocks across everything in the prompt, the pasted error included. It is
a coarse net over the shapes that recur, **not a guarantee** — a secret that does not look
like one gets through.

**The error and the evidence are data, never instruction.** The error was pasted by a person
or a script, everything in a report was written by software on a machine we do not control,
and anyone who can name a service on a monitored host can write text into a metrics
snapshot. So:

- the task is in the system prompt; the error and the evidence are in the user message,
  fenced and introduced as untrusted data;
- the fence markers are neutralised if they appear inside, so a payload cannot close its own
  block and have what follows read as our instructions;
- the model gets **no tools, no network and no write path**. The worst a successful injection
  achieves is a misleading paragraph in a panel labelled as model-written;
- the answer is parsed against a schema, clamped, and rendered as text. It never becomes a
  command, a query, or a field anything dispatches on.

**At rest, reports are encrypted** under the master key, bound to the tenant and host they
belong to. A row moved onto another host fails to decrypt rather than being used as that
host's evidence. Explanations are not stored at all.

**Nothing sensitive is logged.** The server logs the host, provider, model and token counts
of each explanation; it does not log the error or the explanation, which restate a customer's
host state.

---

## 5. The API

### Explaining an error

```
POST /api/explain
{ "host": "web01", "error": "PROBLEM: web01/disk_c is CRITICAL: C:\\ used 95.2% > 90%", "check": "disk_c" }
```

- `host` — the host's id, or its hostname (not case-sensitive). A hostname shared by more
  than one host is refused with `409` and the ids to choose from, rather than explained
  against whichever came first.
- `error` — the error as the monitoring system reported it. Up to 4000 characters.
- `check` — optional. A command (`check_drivesize`) or an alias (`disk_c`). Without it, the
  newest report whose alias — or failing that, command — appears in the error text is used,
  so a pasted `web01/disk_c is CRITICAL` finds `disk_c` without being told.

The evidence:

- **the check** — the agent's latest report of the matched check: its output, perfdata,
  thresholds, arguments, who ran it;
- **the snapshot** — the host's latest metrics snapshot: the newest report carrying one,
  whichever check it came with. Its age is given to the model, which is told to take it into
  account;
- **the facts** — the agent's inventory and every imported source;
- the host's name and fleet tags.

Any of these may be missing — a host that has reported nothing still has facts, and one with
no facts may still have a snapshot — and the prompt says which are, so the model does not
assume it saw them.

```json
{
  "host_id": "01JB…",
  "hostname": "web01",
  "explanation": {
    "summary": "The system drive on web01 is essentially full...",
    "relevant_evidence": ["C:\\ used = 95.2% against a critical threshold of 90%"],
    "likely_causes": ["IIS logs in C:\\inetpub\\logs have not been rotated"],
    "suggested_checks": ["Check the age of files under C:\\inetpub\\logs"],
    "confidence": "high"
  },
  "check":    { "id": "01JC…", "command": "check_drivesize", "alias": "disk_c", "status_word": "CRITICAL", "context_state": "captured", "metrics_count": 521, "reported_at": 1793437964 },
  "snapshot": { "id": "01JC…", "command": "check_drivesize", "alias": "disk_c", "status_word": "CRITICAL", "context_state": "captured", "metrics_count": 521, "reported_at": 1793437964 },
  "facts_sources": ["agent", "import:cmdb"],
  "provider": "anthropic",
  "model": "claude-haiku-5-5",
  "input_tokens": 6120,
  "output_tokens": 410
}
```

`confidence` is how well the evidence supports the explanation, and is worth showing next to
it. A `low` usually means the host had no snapshot; the fix is on the agent side
(`capture metrics = true` under `[/settings/core/failed checks]`).

| answer | when |
|---|---|
| `200` | explained |
| `400` | `error` or `host` empty, or `error` over 4000 characters |
| `404` | no such host in this tenant |
| `409` | the hostname matches several hosts; or explanations are not enabled or are misconfigured for this tenant |
| `429` | the tenant's daily budget is spent |
| `502` | the provider failed or its answer was unusable; the body says why |

Any role may ask: explaining is reading, and the budget bounds what it costs.

### The evidence itself

- `GET /api/hosts/{id}/contexts` — the host's stored reports, newest first: one per check,
  with `context_state` (whether a snapshot came with it, and if not why) and `metrics_count`.
- `GET /api/hosts/{id}/contexts/{context_id}` — one report, with the report verbatim.
- `DELETE /api/hosts/{id}/contexts/{context_id}` — remove one. Requires a role that can
  change configuration.

Retention: a report is dropped 30 days after it arrived unless the check reports again, and a
host keeps at most 200 checks' reports.
