# Deployment

Reference for running `nsclient-fleet` in production — as an internet-facing multi-tenant
service on a single VM, or single-tenant on hardware you control. Same binary either way; the
differences are environment variables.

---

## 1. What gets deployed

One statically-linked binary. No container runtime, no reverse proxy, no external database,
no object store.

| Component        | Where it lives                | Notes                                     |
| ---------------- | ----------------------------- | ----------------------------------------- |
| Binary           | `/opt/nsclient-fleet/nsclient-fleet`      | musl static; the frontend is embedded in it |
| SQLite database  | `/opt/nsclient-fleet/data/fleet.db`      | WAL mode                                  |
| Bundle store     | `/opt/nsclient-fleet/data/bundles/`     | local filesystem                          |
| ACME cache       | `/opt/nsclient-fleet/data/acme/`        | account key + issued certificates         |
| Agent server cert| `/opt/nsclient-fleet/data/mtls-server.{crt,key}` | **agents pin this** — see §4     |
| Config           | `/etc/nsclient-fleet/env`               | mode 640, `root:nsclient-fleet`                     |
| Service          | `/etc/systemd/system/nsclient-fleet.service` | hardened unit           |

Any Linux host will do. Releases cover x86-64 and ARM64, both statically linked against musl,
so distribution and libc version do not matter. Two vCPUs and 2 GB of RAM run a fleet of a few
thousand hosts comfortably; disk is whatever your bundles need plus room for the database.

**The design point is a single machine** — there is no horizontal scaling story, by choice.
SQLite on local disk and an in-process TLS terminator are what make the whole thing one file
to deploy and one file to back up. See [§13](#13-capacity-and-sizing) for what actually runs
out first.

---

## 2. Ports and firewall

**Inbound 443 is the only application port.** The operator UI, agent mTLS, and Let's
Encrypt challenges all share it.

| Port | Direction | Purpose                                          |
| ---- | --------- | ------------------------------------------------ |
| 443  | inbound   | everything (UI, API, agents, ACME)               |
| 22   | inbound   | SSH for deploys — restrict to your own addresses |
| 80   | —         | **not used.** Issuance is TLS-ALPN-01, not HTTP-01 |
| 587  | outbound  | SMTP for magic links, if you use an SMTP relay   |

Sharing one port matters beyond tidiness: agents sit inside customer networks whose egress
filters routinely permit 443 and nothing else. A dedicated agent port is a support ticket on
every locked-down site.

### How one port carries three protocols

The server reads the ClientHello *before* choosing a TLS configuration, and dispatches on
ALPN (`crates/server/src/mux.rs`):

| Client offers        | Gets                                            | Router          |
| -------------------- | ----------------------------------------------- | --------------- |
| ALPN `acme-tls/1`    | throwaway challenge certificate                 | none — handshake only |
| ALPN `nsclient-fleet/1`        | pinned self-signed cert; **client cert required** | agent (`/agent/v1/*`) |
| anything else        | Let's Encrypt cert; no client cert requested     | operator UI + API |

Consequences worth internalising:

- **An agent that does not send ALPN `nsclient-fleet/1` lands on the browser branch**, is served a
  certificate it does not trust, and fails its pin check. That is the single most likely
  cause of "the agent can't connect" after a client rewrite. The constant is a wire
  contract: `fleet_proto::AGENT_ALPN`.
- **Anything that terminates TLS between agent and server breaks this** — a Cloudflare
  orange-cloud proxy, an inspecting middlebox, most L7 load balancers. Keep DNS grey-clouded
  and pass TCP through unmodified.
- Browsers are never asked for a client certificate, so no certificate-picker dialog, and
  the DNs of tenant CAs are never broadcast to visitors.

`MTLS_SNI` adds a hostname fallback for a TLS stack that genuinely cannot set ALPN. It is
off by default on purpose: with it on, any ALPN-less probe (`openssl s_client` without
`-alpn`) reaches the agent branch and gets a certificate request.

---

## 3. DNS

Point the `ACME_DOMAINS` name at the VM's public IP **before first start** — Let's Encrypt's
TLS-ALPN-01 challenge needs the name to resolve to you.

```
app.example.com.   A     203.0.113.10
app.example.com.   AAAA  2a01:4f8:...        # optional
```

Any DNS host works. If yours also offers reverse proxying — Cloudflare's orange cloud is the
one people hit — keep this record **unproxied / DNS-only**. Proxying terminates TLS, which
breaks both ACME issuance and agent mTLS in one click.

---

## 4. Certificates — two of them, two trust models

This trips people up, so it is worth stating plainly. The server holds **two unrelated
server certificates** on the same port.

**The web certificate** is issued by Let's Encrypt, renewed automatically, cached in
`data/acme/`. Browsers validate it against the public WebPKI. If it is lost the server just
re-issues.

**The agent certificate** (`data/mtls-server.crt` + `.key`) is self-signed and generated on
first start. It is handed to each agent at enrollment as `mtls_server_cert_pem`, and agents
trust *it alone* — not the WebPKI. This is deliberate: agent connectivity does not depend on
ACME succeeding, which is what makes on-prem and air-gapped installs work identically.

> **If you lose `data/mtls-server.key`, every enrolled agent is stranded.** They cannot
> recover on their own, because renewal itself requires a working mTLS session. Recovery is
> re-enrolling the entire fleet by hand. Back this file up (§8), and treat any
> "persisted mTLS server cert unusable — regenerating" line in the log as an incident.

The certificate is regenerated only when its SAN no longer covers `MTLS_HOST` or it is
within 30 days of expiry — both of which invalidate every pinned copy, so both log loudly.

`MTLS_HOST` therefore must equal the hostname agents dial. It defaults to the host part of
`BASE_URL`, which is correct for a normal single-name deployment; set it explicitly only if
you also set `MTLS_SNI`.

Client certificates issued to hosts live 90 days (`client_cert_lifetime_days`) and agents
renew themselves via `/agent/v1/renew`.

---

## 5. Environment reference

Set in `/etc/nsclient-fleet/env`. Every variable except `MASTER_KEY` has a working default.

### Required

| Variable     | Notes                                                                     |
| ------------ | ------------------------------------------------------------------------- |
| `MASTER_KEY` | 32 bytes, base64. Encrypts tenant CAs and host overrides. `openssl rand -base64 32` |
| `BASE_URL`   | Public URL. Builds magic links, the install one-liner, and the agent URL   |

**`MASTER_KEY` is not recoverable.** Lose it and every tenant CA and host override in the
database becomes undecryptable. Store a copy outside the VM and outside its backups.

### Listeners

| Variable       | Default          | Notes                                                        |
| -------------- | ---------------- | ------------------------------------------------------------ |
| `LISTEN_HTTPS` | `0.0.0.0:443`    | The shared port, used when ACME is on                        |
| `LISTEN`       | `0.0.0.0:3000`   | Plain HTTP; used **only** when ACME is off                   |
| `LISTEN_MTLS`  | unset with ACME on; `0.0.0.0:9443` with ACME off | Setting it binds a dedicated agent port *in addition* to the mux. Leave unset in production |
| `MTLS_URL`     | derived          | Overrides the URL handed to agents. For proxies/NAT where the reachable address differs from `BASE_URL` |
| `MTLS_SNI`     | unset            | Hostname that also routes to the agent branch, for TLS stacks without ALPN |
| `MTLS_HOST`    | host of `BASE_URL` | SAN of the pinned agent certificate. Changing it regenerates that cert |
| `MTLS_STATE_DIR` | `data`         | Where `mtls-server.{crt,key}` live                           |

### TLS / ACME

| Variable         | Default      | Notes                                                     |
| ---------------- | ------------ | --------------------------------------------------------- |
| `ACME_DOMAINS`   | unset        | Comma-separated. **Setting this enables production mode**  |
| `ACME_CONTACT`   | unset        | Email registered with the ACME account; required with the above |
| `ACME_CACHE_DIR` | `data/acme`  | Persist it, or restarts re-issue and hit rate limits       |
| `ACME_STAGING`   | `false`      | Use the staging directory while testing a deploy           |
| `COOKIE_SECURE`  | `false`      | **Set `true` in production**                               |

### Storage

| Variable        | Default            |
| --------------- | ------------------ |
| `DATABASE_PATH` | `data/fleet.db`     |
| `BUNDLE_DIR`    | `data/bundles`     |

### Email, signup, limits

| Variable                                                | Default | Notes                                  |
| ------------------------------------------------------- | ------- | -------------------------------------- |
| `SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` | unset   | All five or none; falls back to stdout |
| `TURNSTILE_SECRET`                                      | unset   | Cloudflare Turnstile siteverify secret |
| `DAILY_EMAIL_BUDGET`                                    | `5000`  | Global cap; sends past it are dropped  |
| `PLATFORM_ADMIN_EMAILS`                                 | unset   | Comma-separated. Grants the platform console — see below |

Whether self-service signup is open is **not** an environment variable: it is a switch in the
platform console, so it can be closed without a redeploy. See [§14](#14-the-platform-console).

### On-prem

| Variable                 | Default | Notes                                        |
| ------------------------ | ------- | -------------------------------------------- |
| `ON_PREM`                | `false` | Disables signup + magic links; password login |
| `ON_PREM_ADMIN_EMAIL`    | —       | Required when `ON_PREM=true`                 |
| `ON_PREM_ADMIN_PASSWORD` | —       | Required when `ON_PREM=true`                 |
| `BOOTSTRAP_JWT_SECRET`   | `MASTER_KEY` | Override only to separate the two keys  |

---

## 6. First-time VM setup

```bash
# As root on a fresh VM
curl -L https://github.com/mickem/nsclient-fleet-server/releases/latest/download/bootstrap-vm.sh | bash
```

The script creates the `nsclient-fleet` system user (no shell), lays out `/opt/nsclient-fleet/{,data,data/bundles,data/acme}`
and `/etc/nsclient-fleet`, installs the systemd unit, and writes a template `/etc/nsclient-fleet/env`.

Then:

1. Edit `/etc/nsclient-fleet/env` — at minimum `MASTER_KEY`, `BASE_URL`, `ACME_DOMAINS`,
   `ACME_CONTACT`, `COOKIE_SECURE=true`.
2. Confirm DNS resolves to this VM.
3. Install the binary at `/opt/nsclient-fleet/nsclient-fleet` (`chown nsclient-fleet:nsclient-fleet`, mode 755).
4. `systemctl enable --now nsclient-fleet`

Firewall: allow 443 from anywhere and 22 from your own addresses. Nothing else.

---

## 7. Releasing and deploying

`.github/workflows/release.yml` builds the frontend once and shares it, so every binary
embeds byte-identical assets, then builds the server for four targets and attaches them to
a GitHub Release along with `SHA256SUMS`.

| Asset | Platform |
| ----- | -------- |
| `nsclient-fleet-x86_64-unknown-linux-musl` | Linux x64, static |
| `nsclient-fleet-aarch64-unknown-linux-musl` | Linux ARM64, static |
| `nsclient-fleet-x86_64-pc-windows-msvc.exe` | Windows x64 |
| `nsclient-fleet-aarch64-pc-windows-msvc.exe` | Windows ARM64 |

### Versions come from git tags

`codacy/git-version` derives the version from tag history, not from `Cargo.toml`: it takes
the most recent tag and bumps it. Patch by default; put `feature:` or `breaking:` in a
commit message to bump minor or major instead.

That version is resolved once, before anything is built, and used for **both** the release
name and the version compiled into the binary — so `nsclient-fleet --version` always matches
the release it came from. `Cargo.toml`'s version survives only as the fallback for local
builds, where no CI-injected value exists.

The mechanism: the `version` job exports it, the build matrix receives it as
`FLEET_BUILD_VERSION`, and `main.rs` reads it with `option_env!`. Two things make that
reliable and are easy to break — `Cross.toml` must list the variable under
`[build.env] passthrough` or the containerised musl builds silently fall back to the
manifest version, and `crates/server/build.rs` must keep its
`cargo:rerun-if-env-changed=FLEET_BUILD_VERSION` or a cached target directory will hand out
a binary stamped with the previous version. The release workflow's smoke test asserts the
binary reports the expected version, which catches both.

**Anchor the sequence once.** With no tags in the repository, git-version starts from
`0.0.x`, which is lower than the `0.1.0` currently in `Cargo.toml`. Tag `v0.1.0` once and
everything after it reads sensibly.

### Release candidates come from main

Every commit to `main` — in practice every merge — produces a **draft prerelease** named
`v<version>-rc.<run number>`. There is always a built, downloadable artifact set for the
tip of main, and no ceremony is needed to get one. `-rc.N` is a semver prerelease, so
`v0.1.1-rc.7` correctly sorts before the eventual `v0.1.1`.

Two properties worth knowing:

- **A draft does not create its git tag.** GitHub only creates it when someone publishes
  the draft, so RC drafts never pollute the tag namespace and can be deleted freely.
- **Drafts are visible to collaborators only**, never to the public.

`target_commitish` pins each RC to the commit it was built from, so publishing an older
draft tags that commit rather than wherever main has since moved.

RC drafts accumulate — one per merge. They cost nothing but clutter; prune with:

```bash
gh release list --limit 100 --json tagName,isDraft \
  --jq '.[] | select(.isDraft) | select(.tagName | test("-rc\\.")) | .tagName' \
  | tail -n +11 | xargs -r -n1 gh release delete --yes
```

The RC build does not wait for CI. Tests run in parallel on the same commit, so check the
commit is green before publishing a draft — that human step is the gate.

### Cutting a real release

Push a tag. On a tag the tag *is* the version — git-version is skipped entirely, so what
you name is exactly what gets released and compiled in:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

The tag you push also becomes the base that subsequent RCs bump from, so cutting a real
release is what advances the RC series.

Pushing commits and a tag together (`git push --follow-tags`) triggers two runs: an RC
draft for the branch push and the real release for the tag. Harmless, just redundant.

### Verifying and rehearsing

Verify what you downloaded before installing it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

The Linux builds go through `cross`; `Cross.toml` installs CMake into the build container
because `aws-lc-sys` needs it and the stock images do not have it. The Windows builds are
native on `windows-latest`, with NASM installed for `aws-lc-sys`, and the ARM64 one is
cross-compiled with the MSVC ARM64 toolchain.

To exercise the whole matrix without producing any release, run the workflow manually
(Actions → Release → Run workflow). It builds and uploads every target as a workflow
artifact and stops before publishing.

Then push it to the VM:

```bash
VM_HOST=app.example.com VM_USER=deploy ./scripts/deploy.sh
```

`deploy.sh` copies the artifact to `/tmp`, installs it as `nsclient-fleet:nsclient-fleet` mode 755, restarts the
service, and tails the journal.

There is **no graceful shutdown for in-flight requests** — `TimeoutStopSec=30` gives them 30
seconds. Agents retry on their own schedule, so a restart is not fleet-visible.

**Rollback** is the same command against an older artifact:

```bash
ARTIFACT=./nsclient-fleet-v0.1.0 VM_HOST=app.example.com ./scripts/deploy.sh
```

Migrations are forward-only; check that the older binary tolerates the current schema
version before rolling back across a migration.

---

## 8. First boot and verification

```bash
sudo journalctl -u nsclient-fleet -f
```

Expect, in order:

```
starting nsclient-fleet
migrations applied
generated and persisted mTLS server cert     (first boot only)
ACME enabled — running HTTPS on 0.0.0.0:443
shared-port listener up (operator UI + agent mTLS + ACME)
```

First certificate issuance takes 10–30 seconds. Then:

```bash
# Confirm which build actually landed. Answered before config is read, so it works
# without MASTER_KEY and on a box that is not configured yet.
/opt/nsclient-fleet/nsclient-fleet --version

# Web branch — expects OK over a publicly-trusted certificate
curl https://app.example.com/healthz

# Agent branch — expects a certificate request, then a handshake failure (we sent none)
openssl s_client -connect app.example.com:443 -alpn nsclient-fleet/1 </dev/null 2>&1 \
  | grep -E "Acceptable client certificate|ALPN protocol"
```

The second command proving `ALPN protocol: nsclient-fleet/1` and asking for a client certificate is
the check that the mux is routing. If it instead returns the Let's Encrypt certificate and
no certificate request, agents will not be able to connect.

---

## 9. Backups and restore

Everything stateful is under `/opt/nsclient-fleet/data/` plus `/etc/nsclient-fleet/env`.

| Path                    | Lost means                                            |
| ----------------------- | ----------------------------------------------------- |
| `data/fleet.db`          | Everything — tenants, hosts, config, audit             |
| `data/mtls-server.{crt,key}` | **Whole fleet stranded**; every host must re-enroll |
| `data/bundles/`         | Bundle content; assignments survive but downloads 404  |
| `data/acme/`            | Only a re-issue (watch Let's Encrypt rate limits)      |
| `/etc/nsclient-fleet/env`         | `MASTER_KEY` — tenant CAs and overrides undecryptable  |

Baseline: whatever whole-machine snapshot your host provides, on a daily schedule. That is the
fast path back from a broken box.

Recommended in addition, because provider snapshots live with the provider — push `data/`
off-box nightly to storage somewhere else. Any S3-compatible bucket works; the volume is small
enough that most free tiers cover it.

```bash
# /etc/cron.daily/nsclient-fleet-backup
set -euo pipefail
sqlite3 /opt/nsclient-fleet/data/fleet.db ".backup /tmp/fleet.db"   # consistent copy under WAL
restic -r s3:https://<endpoint>/<bucket> backup \
  /tmp/fleet.db /opt/nsclient-fleet/data/mtls-server.crt /opt/nsclient-fleet/data/mtls-server.key \
  /opt/nsclient-fleet/data/bundles
rm -f /tmp/fleet.db
```

Do not copy `fleet.db` with `cp` while the service runs — use `.backup`, or you may capture a
torn WAL state.

Keep `MASTER_KEY` somewhere that is *not* this backup. A backup that contains both the
database and the key that decrypts it is a single object worth compromising.

**Restore drill** (do this once, before you need it): fresh VM → bootstrap → restore `data/`
→ restore `/etc/nsclient-fleet/env` → start → confirm an existing agent heartbeats without re-enrolling.
That last step is what proves the pinned certificate survived.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
| ------- | ----- | --- |
| Agent: "certificate not trusted" / pin failure | Agent did not send ALPN `nsclient-fleet/1`, so it got the web certificate | Fix the agent's TLS config; or set `MTLS_SNI` and point `MTLS_HOST` at it |
| Agent handshake alert `no_application_protocol` | Agent offered ALPN but neither `nsclient-fleet/1` nor `http/1.1` | Add `nsclient-fleet/1` to the agent's ALPN list |
| Log: "the client presented NO certificate" | Agent's identity is not loaded into its TLS session | Agent-side bug — not a revoked or expired certificate |
| Log: "client certificate is not signed by any known tenant CA" | Stale enrollment, deleted tenant, or rotated CA | Re-enroll the host |
| Log: "persisted mTLS server cert unusable — regenerating" | `MTLS_HOST` changed, or the cert is near expiry | **Stop.** Restore the old cert from backup if `MTLS_HOST` changed by accident; otherwise plan a fleet re-enrollment |
| ACME never issues | DNS does not resolve to the VM, or 443 is filtered, or something terminates TLS in front | Check DNS and firewall; grey-cloud Cloudflare |
| Let's Encrypt rate limit | Repeated issuance, usually a wiped `data/acme/` | `ACME_STAGING=true` while iterating |
| Everything works over `http://…:3000`, nothing on 443 | `ACME_DOMAINS` unset, so the server is in plain-HTTP dev mode | Set `ACME_DOMAINS` + `ACME_CONTACT` |

Useful log filters:

```bash
journalctl -u nsclient-fleet -f -g "mTLS handshake failed"
journalctl -u nsclient-fleet -f -g "acme"
```

---

## 11. Migrating a fleet off a dedicated mTLS port

Only relevant for a deployment that already has agents enrolled against `:9443`.

1. Deploy the muxed binary with `LISTEN_MTLS=0.0.0.0:9443` still set. Both paths now work:
   old agents keep using `:9443`, and `:443` accepts `nsclient-fleet/1`.
2. Roll out an agent build that sends ALPN `nsclient-fleet/1`.
3. Set `MTLS_URL=https://app.example.com` so new enrollments and renewals point at `:443`.
   Agents pick this up at their next renewal.
4. When `journalctl -u nsclient-fleet -g "mTLS listening"` shows no further traffic on the
   dedicated port, unset `LISTEN_MTLS`, restart, and close 9443 on the firewall.

Do not skip step 1. Removing the old port before agents have moved strands them, and they
cannot be recovered remotely.

---

## 12. On-prem deployment

```
ON_PREM=true
ON_PREM_ADMIN_EMAIL=admin@customer.local
ON_PREM_ADMIN_PASSWORD=<strong password>
```

Signup and magic links are disabled; the tenant is fixed and hardcoded to the `onprem` tier,
which skips tier rate limiting entirely — the constraint there is the hardware it runs on,
not a hosted-service cost model.

Most on-prem sites have no public DNS, so ACME is off. That means plain HTTP on `LISTEN`
behind the customer's own TLS terminator, and agents on the dedicated `LISTEN_MTLS` port
(default `9443`) — the mux only exists on the ACME path, because it needs a TLS listener we
own. Agent trust is unaffected: they pin the same self-signed certificate they always did.

If the customer's terminator can pass TCP through on 443, `MTLS_URL` lets you point agents
at whatever address is actually reachable.

### Running it on Windows

Releases include Windows x64 and ARM64 binaries, which is often what an NSClient site wants
— the control plane on the same platform as the fleet. Everything above applies except the
Linux packaging: there is no systemd unit or `bootstrap-vm.sh`, so run it as a Windows
service (`sc.exe create`, NSSM, or a scheduled task) with the same environment variables,
and pick data paths that suit the host:

```
DATABASE_PATH=C:\ProgramData\nsclient-fleet\data\fleet.db
BUNDLE_DIR=C:\ProgramData\nsclient-fleet\data\bundles
MTLS_STATE_DIR=C:\ProgramData\nsclient-fleet\data
```

The private-key hardening in `write_key_restricted` is `#[cfg(unix)]`, so on Windows the
mTLS key inherits directory ACLs — put the data directory somewhere only the service
account and administrators can read. The backup rules in §9 apply unchanged, and
`mtls-server.key` is just as unrecoverable there.

---

## 13. Capacity and sizing

A small VM goes a long way here, and the reason is worth knowing before you size one.

The variable that decides how many hosts a single machine holds is not bandwidth; it is the
per-poll work. Agents poll on an interval (30s by default, floor set per tier), so cost scales
with fleet size × poll rate, and each poll is deliberately cheap.

Desired state is memoized against the tenant's `config_version`, so a steady-state poll
costs one indexed tenant read rather than four SQLite reads plus an AEAD decrypt — measured
at 220.8 µs → 222 ns per computation on a 50-group tenant. Cache hit/miss counters are
available via `DesiredStateCache::stats()`. A configuration change invalidates every host in
that tenant at once, so expect a burst of recomputation after an operator edits a group.

What remains on the per-poll path is the `last_seen_at` write on every heartbeat, which
turns poll rate into SQLite write rate. Coalescing those into a periodic batched write is
the next change that extends the life of a single VM.

---

## 14. The platform console

Everything above is per-tenant. **Platform** in the sidebar is the cross-tenant view: every
tenant on the install, their subscriptions, their users, and whether strangers may sign up.
It is a hosted-service tool — on-prem has one tenant and no signups, so there is nothing
there for it to do.

### Getting the first one

Access is a flag on a user row (`users.is_platform_admin`), not a role. Seed it:

```
PLATFORM_ADMIN_EMAILS=ops@yourcompany.example,you@yourcompany.example
```

At every boot each listed address that has an account is granted the flag; an address with
no account yet gets it the moment that account is created, by signup or invitation. So the
variable works in either order — set it before the first signup, or add it later and
restart.

After that the console is the way to hand the flag around: the toggle on any user row grants
or revokes it, effective on that person's next request. Two things it will not do, both so
the console cannot be locked out of itself: you cannot revoke your own flag, and you cannot
block or delete your own account. Removing a platform admin is therefore always somebody
else's action.

Revoking the flag from an address still listed in `PLATFORM_ADMIN_EMAILS` works, and the
next restart grants it back — the variable is the way in when nobody has the flag, so it has
to keep working. Take the address out of the environment as well if the revocation is meant
to stick; the server logs a warning when this case arises.

The flag grants nothing inside the holder's own tenant — their `role` still decides that —
and it does not open other tenants' fleet data. Hosts, groups, bundles and configuration are
reachable only as a user of that tenant, which the console offers no way around. What it
covers is subscriptions, accounts, and the signup switch.

### Subscriptions

Each tenant has a named tier (defined in code, `crates/core/src/tier.rs`), an optional trial
deadline, and optional numeric overrides on top of the tier. The edit form writes all three
at once, so what is on screen is what the tenant gets — a blank trial field means "no
deadline", i.e. a tenant that has paid.

Changes apply on the tenant's next request. Nothing caches a limit: `tier::effective` is
consulted where each one is enforced. The exception is the per-tier agent rate-limiter
buckets, which are sized per tier name and age out on their own.

The host count carries a **local config** badge when some of the tenant's hosts report
configuration of their own that outranks what the fleet sends them — those hosts are only
partly centrally managed, so what an operator sees in the tenant's UI is not necessarily
what is in force. Only hosts that have actually reported are counted; an agent too old to
answer is left out rather than assumed either way. Which hosts they are is visible on the
tenant's own Hosts page, and nothing about the local configuration itself ever reaches the
server — see [agent-integration.md §2.1](agent-integration.md#21-local-configuration).

A tenant past its trial deadline gets `402 Payment Required` on every `/api/*` call except
`/api/me` and logout — clearing or extending the deadline here un-sticks them immediately,
with no need for them to sign in again.

### Blocking vs. removing a user

**Block** is reversible and immediate: the account, its tenant membership, its audit trail
and its API keys all stay, but nothing authenticates. Their session is deleted, their keys
stop resolving, and the sign-in form issues them no new link — while returning the same
uniform 204 it returns for any address, so a block is not detectable from outside. Unblocking
restores everything without reissuing keys.

**Remove** deletes the row, and with it the user's API keys. Audit entries survive with their
attribution dropped, exactly as for a tenant-level removal. A tenant's *only* owner cannot be
removed — that would leave the tenant with nobody who can manage it and no way back — so
block that account instead, or promote a second owner first.

Every platform action is written to the affected tenant's own audit log, attributed to the
platform admin who took it, with their address in the entry's metadata. A customer can see
that their subscription changed and who changed it.

### The signup switch

`Allow self-service signups` decides whether `POST /api/auth/signup` works and whether the
sign-in page offers the form at all (`/api/public-config`, the only unauthenticated endpoint
that reports it). It is stored in the database, so it survives restarts and takes effect
without a deploy.

Closing it leaves existing tenants alone and does not touch invitations — a tenant's own
admins can still add colleagues. New tenants then come from **New tenant** in the console,
which provisions the CA and bundle-signing key and, given an owner address, emails that
person the sign-in link.
