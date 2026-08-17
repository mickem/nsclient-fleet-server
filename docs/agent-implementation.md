# Building the Agent

This document describes how to implement the real (production) agent for
NSClient Fleet. The protocol is fully pull-based: the agent enrolls once
using a one-time bootstrap token, then drives everything itself over mTLS —
polling for desired state, downloading and verifying bundles, and reporting
back. The server never pushes to the agent.

A working reference client lives in `crates/agent-sim/src/lib.rs`, and the full
lifecycle is exercised end-to-end in `crates/server/tests/fleet_flow.rs` and
`crates/server/tests/poll_flow.rs`. Any real agent should behave identically on
the wire.

Once an agent is enrolled, the day-to-day operating contract (config sync, state
reporting, renewal, error handling) is specified in
[agent-integration.md](agent-integration.md).

## Lifecycle overview

```
install (with bootstrap token)
        │
        ▼
  POST /enroll/v1  ──────────────  public HTTPS, one-time token
        │  cert + CA + bundle-signing key + mTLS URL
        ▼
┌─────────────────────────────────────────────────────┐
│  main loop (all over mTLS)                          │
│                                                     │
│   GET  /agent/v1/desired-state?current_hash=…       │
│     ├─ 304 → sleep next_poll_in_seconds, repeat     │
│     └─ 200 → download + verify bundles, apply       │
│   GET  /agent/v1/bundles/:id     (per bundle)       │
│   POST /agent/v1/state-report    (after applying)   │
│   POST /agent/v1/renew           (before cert expiry)│
└─────────────────────────────────────────────────────┘
```

## 1. Enrollment

The user adds a host in the UI/API; the server returns an `install_command`
containing a **bootstrap token** (a JWT wrapping a one-time nonce, expiring
after `bootstrap_ttl_secs`). The agent is started with this token and:

1. Generates an **Ed25519 keypair**. This is the agent's long-term identity key
   until the next renewal.
2. Builds a PKCS#10 **CSR** from it (CN can be anything, e.g. `client` — the
   server sets the real identity in the issued cert from the token's claims).
3. Sends, over plain public HTTPS:

```
POST {server_url}/enroll/v1
Content-Type: application/json

{
  "bootstrap_token": "<token from install command>",
  "csr_pem": "-----BEGIN CERTIFICATE REQUEST-----…",
  "hostname": "web-01",        // optional
  "os": "linux"                // optional
}
```

Success response (`200`):

```jsonc
{
  "cert_pem": "…",                 // client cert signed by the tenant CA
  "ca_pem": "…",                   // tenant CA cert
  "bundle_signing_pub_pem": "…",   // Ed25519 public key for bundle signatures
  "server_url": "…",               // public API base
  "mtls_url": "…",                 // base URL for all /agent/v1/* calls
  "mtls_server_cert_pem": "…"      // cert to pin when connecting to mtls_url
}
```

Persist **all of this plus the private key** to durable storage (e.g.
`agent-state.json` / a state directory with `0600` permissions). Enrollment
cannot be repeated: the server burns the nonce atomically on first use
(`crates/storage/src/repos.rs`, `mark_enrolled_if_pending`), so a replayed or
expired token gets a `4xx`. If the state file is lost, the user must create a
new host (or re-issue a token) server-side.

Failure handling:

- `401/403` — token invalid, expired, or already used. Do not retry; surface a
  clear error telling the user to generate a new install command.
- `429` — per-tenant enrollment rate limit. Back off and retry with jitter.

## 2. The mTLS client

Every call after enrollment goes to `mtls_url` using:

- **ALPN**: offer `nsclient-fleet/1` — first, with `http/1.1` after it. **Not optional.**
- **Client auth**: the issued `cert_pem` + the locally generated private key.
- **Server trust**: pin `mtls_server_cert_pem` as the only root — do not use
  the system trust store for this connection.

The server side resolves `(tenant_id, host_id)` from the client cert, so no
request body ever carries identity — there is no host-id header or token.

### Why ALPN is mandatory

`mtls_url` usually points at port 443, shared with the operator web UI. The
server picks which TLS configuration to use by reading ALPN out of your
ClientHello: `nsclient-fleet/1` gets the pinned certificate and a client-certificate
request; anything else gets the public web certificate and no client-cert
request. Omit it and the connection *appears* to work at the TCP level, then
fails pin validation with a confusing "untrusted certificate" error.

Send `nsclient-fleet/1` unconditionally. It is harmless against a deployment that runs a
dedicated mTLS port, which advertises both `nsclient-fleet/1` and `http/1.1`.

The constant is defined once, in `crates/proto` (`fleet_proto::AGENT_ALPN`).

## 3. Poll loop: desired state

```
GET {mtls_url}/agent/v1/desired-state?current_hash=<last applied hash>
```

Omit `current_hash` on the very first poll.

Responses:

- **`304 Not Modified`** — you are up to date. Body:
  `{"next_poll_in_seconds": N}`. Sleep `N` seconds, poll again.
- **`200 OK`** — new state:

```json
{
  "state_hash": "…",
  "next_poll_in_seconds": 60,
  "merged_config_json": {},
  "bundles": [
    {
      "id": "…",
      "name": "…",
      "version": "…",
      "sha256": "<hex digest of the bundle bytes>",
      "signature": "<base64 Ed25519 signature>",
      "url": "/agent/v1/bundles/<id>",
      "priority": 10
    }
  ]
}
```

- **`429 Too Many Requests`** — you polled faster than your tier's
  `min_poll_interval_secs`. Honor the `Retry-After` header. Treat
  `next_poll_in_seconds` from previous responses as authoritative cadence; the
  server derives it from the tenant tier, so never hardcode an interval.

Notes:

- `merged_config_json` is currently always `{}` — real configuration lives
  inside bundle contents; the agent is responsible for unpacking and applying
  them (see `crates/server/src/desired_state.rs`).
- `state_hash` covers the merged config **and** the bundle set. Store it only
  after a successful apply, and echo it as `current_hash` on subsequent polls.
- Add jitter to the sleep to avoid thundering-herd across a fleet.

## 4. Bundle download and verification

For each entry in `bundles` (process in ascending `priority` order):

1. `GET {mtls_url}{bundle.url}` — the server re-checks that the bundle is in
   this host's effective set and returns `403` otherwise, so a compromised
   host cannot fetch arbitrary tenant bundles.
2. **Verify integrity**: SHA-256 of the raw bytes must equal `sha256` (hex).
3. **Verify authenticity**: `signature` is a base64 Ed25519 signature **over
   the 32-byte SHA-256 digest** (not over the raw bytes), verified with
   `bundle_signing_pub_pem` obtained at enrollment.
4. Only then unpack (bundles are zip archives) and apply the contents.

Reject and report (via `errors` in the state report) on any mismatch — never
apply an unverified bundle. Cache verified bundles by `(id, sha256)` so an
unchanged bundle in a new desired state is not re-downloaded.

## 5. State report

After applying (or failing to apply) a desired state:

```
POST {mtls_url}/agent/v1/state-report
Content-Type: application/json

{
  "applied_state_hash": "<state_hash you successfully applied, or null>",
  "bundles_installed": [],
  "errors": ["…any apply/verify failures…"],
  "reported_tags": { "os": "linux", "role": "web" },
  "local_config_present": false
}
```

All fields are optional server-side (`crates/server/src/agent_api.rs`,
`StateReport`). Semantics:

- `applied_state_hash` set → server records it and updates `last_seen_at`.
  Omit it (null) when nothing was applied; the server still touches
  `last_seen_at`.
- `reported_tags` → upserted as agent-reported tags. If any value actually
  changed, the server bumps the tenant `config_version`, which can change the
  result of your *next* desired-state poll (tags feed group selectors). The
  call is idempotent — resending identical tags is a no-op — so it is safe to
  send the full tag map every time.
- `errors` → logged server-side; use it for bundle verification or apply
  failures.
- `local_config_present` → whether the host has configuration of its own that
  takes precedence over what you were sent. Send the fact on every report, both
  ways round, and **never** send the configuration itself — it typically holds
  credentials. Omitting the field means "no answer" and leaves any previous
  answer standing. Full contract:
  [agent-integration.md §2.1](agent-integration.md#21-local-configuration).

Report tags early (right after enrollment, before the first apply) so the host
gets matched into groups and receives its real desired state promptly.

## 6. Certificate renewal

Client certs expire (`client_cert_lifetime_days` server config). Well before
expiry (e.g. at 2/3 of lifetime), while the current cert is still valid:

1. Generate a **fresh** Ed25519 keypair and CSR.
2. `POST {mtls_url}/agent/v1/renew` with `{"csr_pem": "…"}` — authenticated by
   the existing mTLS cert; no bootstrap token is involved.
3. Response mirrors enrollment: `cert_pem`, `ca_pem`, `mtls_server_cert_pem`,
   `bundle_signing_pub_pem`. Persist the new key + material **atomically**
   (write temp file, fsync, rename) and swap the in-memory identity. The old
   cert stays valid server-side until its natural expiry, so a crash between
   renew and persist is recoverable as long as you don't delete the old key
   until the new material is durably stored.

Also refresh `bundle_signing_pub_pem` and `mtls_server_cert_pem` from the
renew response — this is how server-side key rotation reaches agents.

There is also `GET {mtls_url}/agent/v1/heartbeat` for a cheap liveness check,
useful at startup to validate the stored identity before entering the loop.

## 7. Suggested agent structure

```
agent
├── identity.rs      // keypair gen, CSR, state file load/store (atomic writes)
├── enroll.rs        // one-shot bootstrap → EnrolledAgent material
├── transport.rs     // mTLS client construction (pinned server cert)
├── poll.rs          // desired-state loop, 304/200/429 handling, jitter
├── bundles.rs       // download, sha256 + Ed25519 verify, cache, unpack
├── apply.rs         // apply bundle contents / local config
├── report.rs        // state-report + tag collection
└── renew.rs         // cert lifecycle
```

Main loop sketch:

```text
load state file
  ├─ none + bootstrap token given → enroll, persist, report initial tags
  └─ none + no token → exit with instructions
heartbeat (sanity-check identity; on cert-expired → surface re-enroll guidance)
loop:
  if cert past renewal threshold → renew + persist
  ds = fetch_desired_state(current_hash)
  if 200:
      for bundle in ds.bundles (by priority): download, verify, stage
      apply all-or-nothing; on success current_hash = ds.state_hash
      report_state(current_hash or null, tags, errors)
  sleep next_poll_in_seconds (+ jitter)
```

## 9. Reference material

| Concern                                             | Reference                                                               |
|-----------------------------------------------------|-------------------------------------------------------------------------|
| Wire-level client (all endpoints)                   | `crates/agent-sim/src/lib.rs`                                           |
| Enrollment server-side                              | `crates/server/src/hosts.rs` (`enroll`)                                 |
| Desired-state / state-report / renew handlers       | `crates/server/src/agent_api.rs`                                        |
| Desired-state computation (tags → groups → bundles) | `crates/server/src/desired_state.rs`                                    |
| Bundle download authz                               | `crates/server/src/bundles.rs` (`download`)                             |
| Route wiring (public vs mTLS router)                | `crates/server/src/lib.rs`                                              |
| End-to-end lifecycle tests                          | `crates/server/tests/fleet_flow.rs`, `crates/server/tests/poll_flow.rs` |

The simulator uses `rcgen` (keys/CSRs), `rustls` + `reqwest` (mTLS),
`ed25519-dalek` (signature verify), and `sha2` — a real Rust agent can reuse
these choices directly; an agent in another language just needs Ed25519,
SHA-256, PKCS#10 CSRs, and mTLS with a pinned server cert.
