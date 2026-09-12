# Installing nsclient-fleet on Linux

Step by step from a bare Linux machine to a working control plane you can sign in to over
HTTPS, with a certificate your browser trusts, and with agents enrolling against it.

This is the walkthrough. [deployment.md](deployment.md) is the reference — every
environment variable, backups, capacity, the platform console. Where the two overlap, this
page is the shorter, more opinionated path.

Two ways to run it, and you only need one:

| | |
| --- | --- |
| **This page** | The binary on the host, under systemd. Nothing to install but one file. |
| [docker.md](docker.md) | The same binary in a container, one command. |

---

## Before you start

Decide three things — the rest follows from them.

**1. The name.** Agents and browsers both dial it, and it ends up inside the certificate
agents pin, so changing it later means re-enrolling every host. A DNS name you control is
best; an IP address works if that is genuinely fixed.

**2. Whether Let's Encrypt can reach it.** That needs a publicly resolvable name pointing
at this machine and inbound 443 from the internet. If yes, use ACME and browsers trust the
certificate with no further work — [deployment.md §3](deployment.md#3-dns) covers it, and
you can skip Step 5 here. If no — an internal name, a lab, an air-gapped site — this page
is the path: the server issues itself a certificate and you tell your browsers to trust it.

**3. One port or two.** With TLS on, the operator UI and agent mTLS share one port; they
are separated by ALPN inside the process, not by port number. Without TLS they cannot, and
agents get their own port. One port is the default and the better answer — see
[deployment.md §2](deployment.md#2-ports-and-firewall).

---

## Step 1 — Lay out the machine

As root on a fresh host:

```bash
curl -L https://github.com/mickem/nsclient-fleet-server/releases/latest/download/bootstrap-vm.sh | bash
```

That creates the `nsclient-fleet` system user (no shell), the directory tree under
`/opt/nsclient-fleet`, a template `/etc/nsclient-fleet/env`, and installs the systemd unit.

Prefer to do it by hand, or the script does not suit your distribution:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin nsclient-fleet
sudo mkdir -p /opt/nsclient-fleet/data/{bundles,acme} /etc/nsclient-fleet
sudo chown -R nsclient-fleet:nsclient-fleet /opt/nsclient-fleet
sudo curl -L -o /etc/systemd/system/nsclient-fleet.service \
  https://github.com/mickem/nsclient-fleet-server/releases/latest/download/nsclient-fleet.service
```

## Step 2 — Install the binary

One statically-linked file. Distribution and libc version do not matter.

```bash
# x86-64; use aarch64-unknown-linux-musl on ARM.
cd /tmp
curl -L -O https://github.com/mickem/nsclient-fleet-server/releases/latest/download/nsclient-fleet-x86_64-unknown-linux-musl
curl -L -O https://github.com/mickem/nsclient-fleet-server/releases/latest/download/SHA256SUMS
grep ' nsclient-fleet-x86_64-unknown-linux-musl$' SHA256SUMS | sha256sum -c -

sudo install -o nsclient-fleet -g nsclient-fleet -m 0755 \
  nsclient-fleet-x86_64-unknown-linux-musl /opt/nsclient-fleet/nsclient-fleet
/opt/nsclient-fleet/nsclient-fleet --version
```

`--version` is answered before any configuration is read, so it works on a machine that is
not configured yet — which makes it the right first check that the binary runs at all.

## Step 3 — Generate the master key

```bash
openssl rand -base64 32
```

<!-- @formatter:off -->
> **Write this down somewhere that is not this machine.** `MASTER_KEY` encrypts every
> tenant CA and every host override in the database. It cannot be recovered or reset:
> start the server with a different one and that data is permanently unreadable. Keep a
> copy in a password manager, and specifically *not* in the backups of this host — a
> backup containing both the key and the database it protects is a backup of plaintext.
<!-- @formatter:on -->

## Step 4 — Write the configuration

`/etc/nsclient-fleet/env`, mode 640, owned `root:nsclient-fleet` — it holds the master key
and the admin password, so the service can read it and nobody else can.

```bash
sudo tee /etc/nsclient-fleet/env >/dev/null <<'EOF'
# --- identity -------------------------------------------------------------
MASTER_KEY=<the base64 string from step 3>
BASE_URL=https://fleet.example.internal:8443

# --- TLS ------------------------------------------------------------------
# Issue and persist a self-signed certificate on first start. Step 5 replaces
# this with one your browsers trust; for ACME instead, see deployment.md §3.
TLS_SELF_SIGNED=true
COOKIE_SECURE=true

# --- listeners ------------------------------------------------------------
LISTEN_HTTPS=0.0.0.0:8443

# --- single-tenant --------------------------------------------------------
# Disables signup and magic links; authenticates one administrator by password.
ON_PREM=true
ON_PREM_ADMIN_EMAIL=admin@example.internal
ON_PREM_ADMIN_PASSWORD=<a strong password>

# --- storage --------------------------------------------------------------
DATABASE_PATH=/opt/nsclient-fleet/data/fleet.db
BUNDLE_DIR=/opt/nsclient-fleet/data/bundles
MTLS_STATE_DIR=/opt/nsclient-fleet/data
TLS_STATE_DIR=/opt/nsclient-fleet/data
EOF
sudo chown root:nsclient-fleet /etc/nsclient-fleet/env
sudo chmod 640 /etc/nsclient-fleet/env
```

Port 8443 rather than 443 so the service does not need a privileged port. Use 443 if you
would rather, and give the unit `AmbientCapabilities=CAP_NET_BIND_SERVICE`.

<!-- @formatter:off -->
> **`BASE_URL` is load-bearing.** It is the address in sign-in links, the address in the
> install command handed to each new host, and — through `MTLS_HOST`, which defaults to its
> hostname — the name inside the certificate agents pin. Set it to what agents will
> actually dial before enrolling anything.
<!-- @formatter:on -->

## Step 5 — Start it

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nsclient-fleet
sudo systemctl status nsclient-fleet
journalctl -u nsclient-fleet -n 30
```

The first start does a lot, and the log says so:

```
generated and persisted mTLS server cert       path=/opt/nsclient-fleet/data/mtls-server.crt host=fleet.example.internal
generated a self-signed web certificate …      path=/opt/nsclient-fleet/data/web-server.crt hosts=["fleet.example.internal", "localhost", "127.0.0.1", "::1"]
HTTPS listening (certificate from disk)        addr=0.0.0.0:8443 self_signed=true
shared-port listener up (operator UI + agent mTLS + ACME)
```

Two certificates, and they are not interchangeable — see
[§4 of deployment.md](deployment.md#4-certificates--two-of-them-two-trust-models). The
short version:

| File | Who trusts it | If you lose it |
| ---- | ------------- | -------------- |
| `web-server.crt/.key` | Browsers, once you tell them to | Regenerated on next start; browsers warn again |
| `mtls-server.crt/.key` | Every enrolled agent, by pinning | **Every agent is stranded** and must be re-enrolled |

Check it answers:

```bash
curl -k https://localhost:8443/healthz     # → OK
```

`-k` because nothing trusts the certificate yet. That is the next step.

## Step 6 — Make the certificate trusted

The generated certificate encrypts the connection, but no browser trusts it, so every visit
costs a click-through — and a warning you click through every day is a warning you will
also click through on the day it means something.

Two ways to fix that. Pick by how many machines you have.

### Option A — mkcert (one or two machines, a lab)

[mkcert](https://github.com/FiloSottile/mkcert) is a small local CA: it issues a
certificate for your name and installs its root into your trust stores.

Install it on your **workstation** — that is where the browser is, and where the root has
to end up:

```bash
sudo apt install mkcert libnss3-tools     # Debian / Ubuntu
mkcert -install
```

Issue a certificate covering every name and address you will type in the URL bar. A
certificate for `fleet.example.internal` is not valid for that machine's IP:

```bash
mkcert -cert-file fleet.pem -key-file fleet.key \
  fleet.example.internal 10.0.0.42 localhost 127.0.0.1
```

Copy it to the server and point the service at it:

```bash
scp fleet.pem fleet.key you@fleet.example.internal:/tmp/

# on the server
sudo install -o nsclient-fleet -g nsclient-fleet -m 0644 /tmp/fleet.pem /opt/nsclient-fleet/data/web.pem
sudo install -o nsclient-fleet -g nsclient-fleet -m 0600 /tmp/fleet.key /opt/nsclient-fleet/data/web.key
rm /tmp/fleet.pem /tmp/fleet.key
```

Swap `TLS_SELF_SIGNED=true` in `/etc/nsclient-fleet/env` for:

```
TLS_CERT=/opt/nsclient-fleet/data/web.pem
TLS_KEY=/opt/nsclient-fleet/data/web.key
```

```bash
sudo systemctl restart nsclient-fleet
```

`TLS_CERT`/`TLS_KEY` and `TLS_SELF_SIGNED` are mutually exclusive and the server refuses to
start with both — either it generates the certificate or you supply it, and a deployment
should not have to guess which one it got.

<!-- @formatter:off -->
> **A local CA is trusted for every site on that machine**, not just this one. Keep
> `rootCA-key.pem` (in `$(mkcert -CAROOT)`) off shared storage, and move to Option B once
> more than a couple of people need to reach the UI. `mkcert -uninstall` removes the root.
<!-- @formatter:on -->

### Option B — your own internal CA (an organisation)

If you already have an internal CA, this is a certificate request like any other. Issue one
for `BASE_URL`'s hostname, install the certificate and key as above, and set `TLS_CERT` /
`TLS_KEY`. Every machine that already trusts your CA trusts this server with no per-machine
step — which is the whole reason to prefer it once there is more than one browser involved.

If `TLS_CERT` is a chain, put the leaf first and the intermediates after it, in one file.

### Option C — distribute the generated certificate

Small, closed estates sometimes prefer no CA at all: take
`/opt/nsclient-fleet/data/web-server.crt` and install it directly as a trusted certificate
on the handful of machines that need it. It works, and it is the least pleasant to live
with — every regeneration is another round of distribution.

### Verify

```bash
openssl s_client -connect fleet.example.internal:8443 \
  -servername fleet.example.internal </dev/null 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName
```

The issuer should be your CA, and the SAN list should contain the name you are dialling.
Then load the UI: no warning, and a padlock.

## Step 7 — Open the firewall

```bash
# ufw
sudo ufw allow 8443/tcp
sudo ufw allow from <your addresses> to any port 22 proto tcp

# firewalld
sudo firewall-cmd --permanent --add-port=8443/tcp && sudo firewall-cmd --reload
```

That is the whole list. One application port carries the UI, the API and every agent;
there is no second port unless you disable TLS, and outbound 587 only matters if you use an
SMTP relay.

<!-- @formatter:off -->
> **Nothing may terminate TLS in front of this.** An inspecting proxy, a Cloudflare orange
> cloud, most L7 load balancers — each of them breaks agent mTLS, because agents
> authenticate with a client certificate against a server certificate they pinned. Pass TCP
> through unmodified, or put the server directly on the network.
<!-- @formatter:on -->

## Step 8 — Sign in and enroll a host

Open `https://fleet.example.internal:8443/` and sign in with `ON_PREM_ADMIN_EMAIL` and
`ON_PREM_ADMIN_PASSWORD`.

Then **Hosts → Add host**. The install command it returns carries a one-time bootstrap
token, good for an hour:

```
nscp enroll --server https://fleet.example.internal:8443 --token <bootstrap-token>
```

Run that on the machine you are adding. NSClient++ is a separate product;
[Central management with NSClient Fleet](https://docs.nsclient.org/setup/fleet/) is the
walkthrough from its side — enrolling, trusting this server's certificate, and what changes
on the agent afterwards. What matters on this side:

- **The agent verifies `BASE_URL`'s certificate at enrollment**, against the host's own CA
  bundle. With a self-signed or internal-CA certificate the agent needs
  `--ca /path/to/ca.pem`. This is the one place the web certificate matters to an agent;
  after enrollment it pins the *mTLS* certificate and never consults the public trust store
  again.
- **The token is one-time** and is burned on first use. A failed attempt needs a new one.
- **The host appears as pending** until its first poll, then moves to its real status.

The wire contract, if you are implementing an agent rather than using NSClient++, is in
[agent-implementation.md](agent-implementation.md).

## Step 9 — Back up the right four things

```bash
sudo systemctl stop nsclient-fleet
sudo tar czf /var/backups/fleet-$(date +%F).tgz \
  -C /opt/nsclient-fleet data
sudo systemctl start nsclient-fleet
```

That covers the database, the bundles, and both certificates. It does **not** cover
`MASTER_KEY`, and must not: the key belongs somewhere the backup is not, or the encryption
protects nothing. See [§9 of deployment.md](deployment.md#9-backups-and-restore) for the
hot-copy version that does not need a stop.

---

## Troubleshooting

**It will not start.** `journalctl -u nsclient-fleet -n 50`. Configuration errors are
deliberately fatal and name the variable — a server that started with half its TLS
configuration understood would be worse than one that refused.

| Message | Cause |
| ------- | ----- |
| `MASTER_KEY required` | Not set, or not 32 bytes of base64 |
| `ACME_DOMAINS and TLS_CERT/TLS_SELF_SIGNED are both set` | Two certificate sources; pick one |
| `TLS_CERT and TLS_KEY must be set together` | Only one of the pair |
| `read TLS certificate …` | Path wrong, or unreadable by the service user |
| `… are not a matching certificate and key` | Mismatched pair, or the files are swapped |

**The browser warns.** Either the issuing CA is not installed where the browser runs, or
the name you typed is not in the certificate's SAN list — the `openssl` command in Step 6
shows both. Firefox keeps its own trust store and ignores the system one.

**An agent cannot connect after enrolling.** Almost always something terminating TLS in
between (Step 7), or a changed `MTLS_HOST`. A regenerated mTLS certificate logs loudly:

```
persisted mTLS server cert unusable — regenerating. Agents enrolled against the old
cert cannot connect and must be re-enrolled.
```

Treat that line as an incident, not a note.

**The UI loads over HTTP but not HTTPS.** `TLS_SELF_SIGNED=false` with no `TLS_CERT` means
plain HTTP on `LISTEN`, and agents then need their own port on `LISTEN_MTLS` (9443 by
default). That is a valid way to run behind your own terminator, but it is not what Step 4
configures.

---

## Next

- [docker.md](docker.md) — the same server as a container.
- [deployment.md](deployment.md) — every environment variable, ACME, sizing, the platform
  console.
- [ca-rotation-playbook.md](ca-rotation-playbook.md) — rotating a tenant CA, planned or
  after a compromise.
