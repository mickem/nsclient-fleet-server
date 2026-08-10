# Agent Integration Reference (post-enrollment)

The operating contract for an agent that is **already enrolled**: how it keeps its
configuration in sync, reports state, and maintains its certificate.
For enrollment itself and a suggested agent architecture, see
[agent-implementation.md](agent-implementation.md).

Everything below happens over **mTLS** against the `mtls_url` received at enrollment,
authenticated by the client certificate — no tokens, no identity in request bodies. The
server resolves `(tenant_id, host_id)` from the certificate on every request.

## The sync loop at a glance

```
loop:
  GET /agent/v1/desired-state?current_hash=<h>
    304 → sleep next_poll_in_seconds (+ jitter), continue
    200 → download missing bundles → verify → apply → render INI → restart NSClient
          POST /agent/v1/state-report { applied_state_hash, reported_tags, errors }
  POST /agent/v1/renew   (when cert has < 14 days left)
```

The server never pushes. Every change an operator makes (tags, groups, assignments,
overrides, new bundle versions) reaches the agent through the next poll.

## 1. Config sync

### 1.1 Poll

```
GET {mtls_url}/agent/v1/desired-state?current_hash=<last successfully applied hash>
```

Omit `current_hash` only when the agent has never applied anything (or lost its state).

**`304 Not Modified`** — nothing to do. Body: `{"next_poll_in_seconds": N}`. Sleep `N`
seconds plus a small jitter (±10%) and poll again. `N` comes from the tenant's tier —
never hardcode a poll interval.

**`200 OK`** — new desired state:

```json
{
  "state_hash": "3f2a…",
  "next_poll_in_seconds": 30,
  "merged_config_json": {},
  "bundles": [
    { "id": "01J…", "name": "sql-monitoring", "version": "2.1.0",
      "sha256": "<hex>", "signature": "<base64>",
      "url": "/agent/v1/bundles/01J…", "priority": 100 }
  ]
}
```

- `bundles` is ordered by **ascending priority** — apply in exactly this order so the
  agent's merge matches the server's layering.
- `merged_config_json` is currently always `{}`: all real configuration lives inside
  bundle contents, and host overrides are folded into `state_hash` server-side. Treat the
  field as a forward-compatibility slot — merge it like a bundle patch if it is ever
  non-empty.
- `state_hash` covers the bundle set (ids, digests, priorities) and the merged config.
  Persist it only after a fully successful apply.

**`429 Too Many Requests`** — the agent polled faster than the tier's floor or exceeded
its per-host request budget. Honor the `Retry-After` header, then resume the normal
cadence. A 429 is always a pacing bug or a restart artifact, never fatal.

### 1.2 Download and verify bundles

For each bundle not already in the local cache (key by `id` + `sha256`):

```
GET {mtls_url}/agent/v1/bundles/{id}
```

Then, in order, before touching the filesystem:

1. **Integrity** — SHA-256 of the downloaded bytes must equal `sha256`.
2. **Authenticity** — `signature` is a base64 Ed25519 signature over the **32-byte
   SHA-256 digest** (not the raw bytes), verified with the `bundle_signing_pub_pem`
   received at enrollment/renewal.

A `403` means the bundle is not in this host's effective set (the server recomputes
membership on every download) — treat it as "desired state changed under me": abandon
this apply cycle and re-poll. A verification failure means the bundle must not be
applied; record it in `errors` on the state report and keep running the previous config.

### 1.3 Apply

A bundle zip contains:

| entry | meaning |
|---|---|
| `bundle.toml` | manifest: name, version, target_os, schema version, declared config keys, script paths |
| `config.json` | a JSON Merge Patch (RFC 7396) fragment |
| `scripts/*` | files to drop on the host at the manifest-declared paths |

Apply procedure (all-or-nothing):

1. Start from `{}` and apply each bundle's `config.json` as a **JSON Merge Patch** in
   the delivered (priority) order: objects deep-merge, scalars and arrays replace
   wholesale, `null` deletes a key.
2. Stage script files from each bundle; higher-priority bundles win path collisions.
3. **Render the merged JSON to NSClient INI.** JSON is the only format on the wire and
   in the control plane; INI exists solely as the final on-disk artifact. The JSON → INI
   mapping is deterministic and schema-driven and lives in the agent.
4. Write config + scripts to a staging directory, then swap atomically (rename) and
   reload/restart NSClient.
5. Only after the swap succeeds, persist `state_hash` as the new `current_hash`.

If any step fails, roll back to the previous config, keep the old `current_hash`, and
report the failure (next section). Never leave the host half-applied.

## 2. State report

After every apply attempt — success or failure — and also right after startup:

```
POST {mtls_url}/agent/v1/state-report
{
  "applied_state_hash": "3f2a…",
  "bundles_installed": [ { "id": "01J…", "version": "2.1.0" } ],
  "errors": [],
  "reported_tags": { "os": "windows", "os_version": "2019", "sql_server_present": "true" }
}
```

All fields are optional. Semantics, exactly as the server implements them:

- `applied_state_hash` present → stored as the host's `current_state_hash` and
  `last_seen_at` is refreshed. This is what makes the UI show **✔ In sync**. Omit it
  (or send `null`) after a failed apply — the server still refreshes `last_seen_at`.
- `reported_tags` → upserted with `source = 'agent'`. Manual (operator-set) tags are
  never touched. If any value actually **changed**, the server bumps the tenant's
  config version — which can change your next desired state, since tags drive group
  membership. Re-sending identical tags is a no-op, so the simplest correct behavior is
  to send the full tag map on every report.
- `errors` → logged server-side against the host. Put bundle verification failures,
  apply failures, and INI render errors here as human-readable strings.

Practical tag guidance: report observed facts (`os`, versions, detected services) —
these are what operators write selectors against, e.g. `sql_server_present = "true"`
pulling the SQL monitoring bundle. Values are strings; booleans by convention are
`"true"` / `"false"`. Report tags **early** (first report right after startup, before
the first poll) so a fresh host lands in its groups before it asks for desired state.

## 3. Certificate lifecycle

Client certs live 90 days. When the current cert is within **14 days** of expiry:

```
POST {mtls_url}/agent/v1/renew
{ "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----…" }
```

- Authenticated by the existing (still-valid) mTLS cert — no bootstrap token.
- Generate a **fresh keypair** for the CSR; only its public key is used (the server
  constructs the certificate identity itself from the mTLS context).
- Response: `{ cert_pem, ca_pem, mtls_server_cert_pem, bundle_signing_pub_pem }`.
  Persist **all four plus the new private key** atomically, then swap the in-memory
  identity. Refreshing `bundle_signing_pub_pem` and `mtls_server_cert_pem` here is how
  server-side key rotation reaches agents — never skip them.
- The old cert stays valid until natural expiry, so a crash between renew and persist
  is recoverable: retry with the old identity.

If the cert expires before renewal (host offline too long), every mTLS call fails at
the handshake. There is no self-service recovery — the operator must issue a new
bootstrap token ("Add host") and the agent re-enrolls.

`GET /agent/v1/heartbeat` remains available as a cheap liveness/identity check (it also
refreshes `last_seen_at`, and returns `403` if the cert was revoked) — useful at
startup before entering the loop.

## 4. Error handling summary

| Response | Meaning | Agent behavior |
|---|---|---|
| `304` on desired-state | up to date | sleep `next_poll_in_seconds` + jitter |
| `429` + `Retry-After` | pacing/budget exceeded | wait exactly `Retry-After`, resume normal cadence |
| `403` on bundle download | bundle no longer in effective set | abandon cycle, re-poll |
| `403` on heartbeat | certificate revoked | stop; operator intervention (re-enroll) |
| TLS handshake failure | cert expired/revoked, or server cert rotated | if before expiry: retry with backoff; if expired: re-enroll |
| `5xx` / network error | transient server trouble | exponential backoff with jitter, cap at ~5× poll interval; keep running last-applied config |

Two invariants above all: **never apply an unverified bundle**, and **never report a
state hash you did not fully apply**. A host that is honestly out-of-sync is a visible,
fixable condition; a host that lies about its state is not.
