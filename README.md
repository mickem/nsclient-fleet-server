# NSClient Fleet

Fleet management control plane for NSClient. One statically-linked binary — embedded web UI,
SQLite, and TLS termination in-process — that runs either as a multi-tenant hosted service or
single-tenant on your own hardware.

## Bootstrap

Prereqs:
- Rust (stable, 1.80+)
- Node 20+ and npm
- `just` task runner — `cargo install just`

```powershell
just setup        # install web deps
just web-build    # produce web/dist
just dev-server   # run the Rust server on http://localhost:3000
```

For frontend HMR during dev, run `just dev-web` (Vite on :5173, proxies `/api` and `/healthz` to :3000) in a second terminal alongside `just dev-server`.

## Verify

```powershell
curl http://localhost:3000/healthz   # → OK
curl http://localhost:3000/          # → React HTML
```

## Layout

Repo root is the Cargo workspace. Crates under `crates/`, frontend under `web/`. The release binary embeds `web/dist/` via `rust-embed` and serves it from a single port.

| crate               | role                                             |
|---------------------|--------------------------------------------------|
| `crates/server`     | axum app, main binary (`nsclient-fleet`)           |
| `crates/core`       | domain types shared across server + agent        |
| `crates/storage`    | sqlx repositories, `BundleStore` trait           |
| `crates/enrollment` | CSR signing, cert issuance, JWT bootstrap        |
| `crates/agent-sim`  | simulated NSClient agent for integration testing |
| `crates/proto`      | wire types shared with the real agent later      |

## Documentation

| Document | What it covers |
| -------- | -------------- |
| [docs/deployment.md](docs/deployment.md) | Running it in production: ports, certificates, every environment variable, backups, troubleshooting |
| [docs/agent-implementation.md](docs/agent-implementation.md) | Writing an agent: enrollment, the bootstrap-token → CSR → mTLS flow |
| [docs/agent-integration.md](docs/agent-integration.md) | The post-enrollment contract: config sync, state reporting, certificate renewal |
| [docs/ca-rotation-playbook.md](docs/ca-rotation-playbook.md) | Rotating a tenant CA or bundle-signing key, planned or after compromise |

## Users and roles

The account that signs up owns the tenant. Owners and admins can invite colleagues from
**Users** in the sidebar; an invitation creates the account and emails a magic link, which is
the only way the invitee signs in — the link is never shown to the inviter.

| role         | fleet | add hosts | configuration | users |
|--------------|-------|-----------|---------------|-------|
| `owner`      | read  | yes       | yes           | yes   |
| `admin`      | read  | yes       | yes           | yes   |
| `add_hosts`  | read  | yes       | no            | no    |
| `view_only`  | read  | no        | no            | no    |

"Configuration" is groups, bundles, assignments, host tags and overrides, and deleting hosts.
Roles are enforced server-side (`crates/core/src/user.rs` defines them; every handler asks a
`can_*` method); the UI only hides controls a role cannot use. A role change applies on the
user's next request, without them signing in again.

The owner cannot be re-roled or removed, and nobody can change their own role or delete their
own account — together that keeps a tenant from locking itself out. Deleting a user signs them
out immediately and leaves their audit entries in place, without attribution.

Invitations are unavailable when `ON_PREM=true`: that mode disables magic links and
authenticates a single administrator from `ON_PREM_ADMIN_EMAIL` / `ON_PREM_ADMIN_PASSWORD`.

## API keys

Every user can mint bearer tokens from **API keys** in the sidebar, for scripting the API.
A key acts as its owner and does exactly what their role allows — so provisioning installers
from CI wants a key belonging to an `add_hosts` account, not an admin one.

```bash
# Provision a host and print the command to run on it
curl -sS -X POST https://app.example.com/api/hosts \
  -H "Authorization: Bearer $NSCLIENT_FLEET_API_KEY" | jq -r .install_command
```

The response also carries `host_id`, `bootstrap_token` and `expires_at`; the token is
single-use and expires in an hour, same as one issued from the UI.

The key itself is shown once at creation — only its SHA-256 reaches the database, alongside a
short prefix (`nsk_a1B2c3D4…`) so keys are still identifiable in the list. Keys are private to
their owner: nobody else can list or revoke them, admins included. Revoking a key, changing
the owner's role, or deleting the owner all take effect on the key's next request.

## Dev environment variables

`MASTER_KEY` is required for any startup that touches encryption (tenant CAs, host overrides). For dev:

```powershell
$env:MASTER_KEY = "$(openssl rand -base64 32)"   # or any 32 bytes base64-encoded
```

All other env vars have working dev defaults. Useful overrides:

| var                                                     | default                 | notes                                                                                                                                                     |
|---------------------------------------------------------|-------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `LISTEN`                                                | `0.0.0.0:3000`          | Plain HTTP listen address (when ACME is off)                                                                                                              |
| `LISTEN_HTTPS`                                          | `0.0.0.0:443`           | HTTPS listen address (only used when `ACME_DOMAINS` is set)                                                                                               |
| `LISTEN_MTLS`                                           | `0.0.0.0:9443` (dev)    | Dedicated mTLS listener. Unset by default in production — agents share `LISTEN_HTTPS` via ALPN. See [deployment](docs/deployment.md#2-ports-and-firewall) |
| `MTLS_HOST`                                             | host of `BASE_URL`      | SAN of the pinned agent cert; changing it regenerates that cert                                                                                           |
| `MTLS_URL`                                              | derived                 | Overrides the URL handed to agents at enrollment                                                                                                          |
| `MTLS_SNI`                                              |                         | Hostname fallback for agents whose TLS stack can't set ALPN                                                                                               |
| `BASE_URL`                                              | `http://localhost:3000` | Public URL — used to build magic links and the install one-liner                                                                                          |
| `DATABASE_PATH`                                         | `data/fleet.db`          | SQLite file                                                                                                                                               |
| `BUNDLE_DIR`                                            | `data/bundles`          | Local bundle store root                                                                                                                                   |
| `ON_PREM`                                               | `false`                 | Disables signup + magic links; enables password admin login                                                                                               |
| `ON_PREM_ADMIN_EMAIL`                                   |                         | Required when `ON_PREM=true`                                                                                                                              |
| `ON_PREM_ADMIN_PASSWORD`                                |                         | Required when `ON_PREM=true`                                                                                                                              |
| `COOKIE_SECURE`                                         | `false`                 | Set `true` in production (HTTPS only)                                                                                                                     |
| `SMTP_HOST` / `_PORT` / `_USER` / `_PASSWORD` / `_FROM` |                         | Magic-link delivery; falls back to stdout when unset                                                                                                      |
| `TURNSTILE_SECRET`                                      |                         | Cloudflare Turnstile siteverify secret (signup gate)                                                                                                      |
| `DAILY_EMAIL_BUDGET`                                    | `5000`                  | Global cap; exceeded sends are silently dropped                                                                                                           |
| `ACME_DOMAINS`                                          |                         | Comma-separated list — enables Let's Encrypt when set                                                                                                     |
| `ACME_CONTACT`                                          |                         | Email registered with the ACME account                                                                                                                    |
| `ACME_CACHE_DIR`                                        | `data/acme`             | Persistent cache so restarts don't re-issue certs                                                                                                         |
| `ACME_STAGING`                                          | `false`                 | Use Let's Encrypt staging directory (for testing)                                                                                                         |
| `BOOTSTRAP_JWT_SECRET`                                  | (= `MASTER_KEY`)        | Override only if you want separate keys                                                                                                                   |

## Production deployment

Full reference: **[docs/deployment.md](docs/deployment.md)**.

The short version: one statically-linked binary on one small Linux VM, SQLite on local disk,
TLS terminated in-process — no container runtime, no reverse proxy, no external database.
**Inbound 443 is the only application port** — the operator UI, agent mTLS, and Let's Encrypt
challenges share it, dispatched on the ClientHello's ALPN (`crates/server/src/mux.rs`). Agents
must offer ALPN `nsclient-fleet/1`; anything that terminates TLS in front of the server (a reverse proxy
that re-encrypts, an inspecting middlebox, most L7 load balancers) breaks them.

```bash
# On a fresh VM, as root
curl -L https://github.com/mickem/nsclient-fleet-server/releases/latest/download/bootstrap-vm.sh | bash
# then edit /etc/nsclient-fleet/env, point DNS at the VM, and:
systemctl enable --now nsclient-fleet

# Deploy a new build from your machine
VM_HOST=app.example.com VM_USER=deploy ./scripts/deploy.sh
```

It also runs single-tenant on your own hardware, including on Windows — set `ON_PREM=true` and
see [On-prem deployment](docs/deployment.md#12-on-prem-deployment).

Two things that cannot be recovered if lost, and are not stored together on purpose:
`MASTER_KEY` (in `/etc/nsclient-fleet/env`) decrypts every tenant CA, and `data/mtls-server.key` is the
certificate the whole fleet pins. See
[Backups and restore](docs/deployment.md#9-backups-and-restore).
