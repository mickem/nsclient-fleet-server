# Installing nsclient-fleet on Windows

Step by step from a bare Windows machine to a working control plane, running as a Windows
service, that you can sign in to over HTTPS and enroll agents against.

This is the walkthrough. [deployment.md](deployment.md) is the reference — every
environment variable, backups, capacity, the platform console. Where the two overlap, this
page is the shorter, more opinionated path. Everything here is single-tenant (`ON_PREM`),
because that is what a Windows install is nearly always for.

Three ways to run it, and you only need one:

| | |
| --- | --- |
| **This page** | The binary on a Windows host, as a real service under the SCM. |
| [linux-install.md](linux-install.md) | The same binary on Linux, under systemd. |
| [docker.md](docker.md) | The same binary in a container, one command. |

Nothing about the agent side differs between them.

---

## Before you start

You need an elevated PowerShell (**Run as administrator**) for the service and firewall
steps, and the same three decisions the Linux guide opens with:

**1. The name.** Agents and browsers both dial it, and it ends up inside the certificate
agents pin, so changing it later means re-enrolling every host. A DNS name you control is
best; an IP address works if that is genuinely fixed.

**2. The port.** This guide uses **9443**. Not 443, which is likely taken on a Windows
server and needs nothing special here but invites a collision with IIS; and specifically
not 8443, which is the NSClient++ agent's own web UI — an agent on this machine would
collide with it.

**3. Where the data lives.** `C:\ProgramData\nsclient-fleet` below. It holds the database,
the bundles and both private keys, so it wants an ACL that the next section sets.

<!-- @formatter:off -->
> **The one Windows-specific caveat.** On Linux the service narrows the permissions of what
> it writes itself (`restrict_dir`, `0700`); that code is `#[cfg(unix)]` and does nothing
> here. On Windows the data directory's ACL is the whole protection, and it is inherited —
> which is why Step 1 sets it before anything is written, rather than after.
<!-- @formatter:on -->

---

## Step 1 — Lay out the machine

From an elevated PowerShell:

```powershell
$Root = "C:\ProgramData\nsclient-fleet"
New-Item -ItemType Directory -Force -Path "$Root\data", "$Root\logs" | Out-Null

# Break inheritance from ProgramData (where Users can create and read), then grant only
# SYSTEM — the account the service runs as — and Administrators.
icacls $Root /inheritance:r
icacls $Root /grant "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F"
icacls $Root
```

The last command should list exactly those two entries. If `BUILTIN\Users` is still in
there, the database — every tenant's encrypted CA key and every session hash — is readable
by any account on this machine.

Install the binary somewhere the service account cannot rewrite it. `Program Files` is
that by default, which is the reason to prefer it over the data directory:

```powershell
New-Item -ItemType Directory -Force -Path "C:\Program Files\nsclient-fleet" | Out-Null
```

## Step 2 — Install the binary

One file, no runtime to install. Pin a version rather than tracking `latest`, and verify it
before running it.

```powershell
$Version = "v0.1.0"
$Base    = "https://github.com/mickem/nsclient-fleet-server/releases/download/$Version"
$Asset   = "nsclient-fleet-x86_64-pc-windows-msvc.exe"   # aarch64-… on ARM64

Invoke-WebRequest "$Base/$Asset"      -OutFile "$env:TEMP\$Asset"
Invoke-WebRequest "$Base/SHA256SUMS"  -OutFile "$env:TEMP\SHA256SUMS"

$expected = (Select-String -Path "$env:TEMP\SHA256SUMS" -Pattern " $Asset$").Line.Split(" ")[0]
$actual   = (Get-FileHash "$env:TEMP\$Asset" -Algorithm SHA256).Hash
if ($actual -ne $expected.ToUpper()) { throw "checksum mismatch — do not run this file" }

Copy-Item "$env:TEMP\$Asset" "C:\Program Files\nsclient-fleet\nsclient-fleet.exe"
& "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --version
```

Every release asset also carries a build provenance attestation, which says the file came
out of this repository's release workflow — a checksum served from the same origin as the
binary only catches a corrupted download. With the [GitHub CLI](https://cli.github.com)
installed:

```powershell
gh attestation verify "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" `
  --repo mickem/nsclient-fleet-server
```

`--version` is answered before any configuration is read, so it works on a machine that is
not configured yet — which makes it the right first check that the binary runs at all.

## Step 3 — Generate the master key and the admin password hash

```powershell
# 32 random bytes, base64. No openssl needed.
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
[Convert]::ToBase64String($bytes)
```

<!-- @formatter:off -->
> Use that form rather than `RandomNumberGenerator::Fill($bytes)`, which exists only in
> PowerShell 7. On Windows PowerShell 5.1 — what a server has out of the box — `Fill` fails
> with `MethodNotFound` and leaves the buffer exactly as it was, which was all zeros. The
> result looks like a key and is `AAAA…`.
<!-- @formatter:on -->

<!-- @formatter:off -->
> **Write this down somewhere that is not this machine.** `MASTER_KEY` encrypts every
> tenant CA and every host override in the database. It cannot be recovered or reset:
> start the server with a different one and that data is permanently unreadable. Keep a
> copy in a password manager, and specifically *not* in the backups of this host — a
> backup containing both the key and the database it protects is a backup of plaintext.
<!-- @formatter:on -->

Then the administrator password. The binary hashes it for you, so the plaintext never has
to be written down in a file that also lands in a backup:

```powershell
& "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --hash-password
```

```
Password: ********
Confirm:  ********

Set ON_PREM_ADMIN_PASSWORD_HASH to the line below (quote it — it contains $):
$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
```

The prompt does not echo, so the password reaches neither the scrollback nor the command
history. See [Producing the hash](#producing-the-hash) for what that string is, how to
script it, and why the hash is preferred over `ON_PREM_ADMIN_PASSWORD`.

## Step 4 — Write the configuration

Windows services do not get an `EnvironmentFile` the way systemd does; what they get is the
*machine* environment, which is readable by every process on the host. So configuration
goes in a file the service reads itself, and the file's ACL is what protects it:

```powershell
$Root = "C:\ProgramData\nsclient-fleet"
@'
# --- identity -------------------------------------------------------------
MASTER_KEY=<the base64 string from step 3>
BASE_URL=https://fleet.example.internal:9443

# --- TLS ------------------------------------------------------------------
# Issue and persist a self-signed certificate on first start. Step 6 replaces
# this with one your browsers trust.
TLS_SELF_SIGNED=true
COOKIE_SECURE=true

# --- listeners ------------------------------------------------------------
LISTEN_HTTPS=0.0.0.0:9443

# --- single-tenant --------------------------------------------------------
# Disables signup and magic links; authenticates one administrator by password.
ON_PREM=true
ON_PREM_ADMIN_EMAIL=admin@example.internal
ON_PREM_ADMIN_PASSWORD_HASH=<the argon2 string from step 3>

# --- storage --------------------------------------------------------------
DATABASE_PATH=C:\ProgramData\nsclient-fleet\data\fleet.db
BUNDLE_DIR=C:\ProgramData\nsclient-fleet\data\bundles
MTLS_STATE_DIR=C:\ProgramData\nsclient-fleet\data
TLS_STATE_DIR=C:\ProgramData\nsclient-fleet\data

# --- logs -----------------------------------------------------------------
# A service has no console and no journal: without this there is no record of
# why one failed to start. Rotated daily, as fleet.log.YYYY-MM-DD.
LOG_FILE=C:\ProgramData\nsclient-fleet\logs\fleet.log
'@ | Set-Content -Path "$Root\env"
```

<!-- @formatter:off -->
> **`@'…'@`, not `@"…"@`.** The single-quoted here-string is the one PowerShell does not
> expand. Paste an argon2 hash into the double-quoted form and `$argon2id`, `$v` and `$m`
> are read as variables that do not exist:
> `ON_PREM_ADMIN_PASSWORD_HASH==19=19456,t=2,p=1`. It fails later, at sign-in, as a
> password that does not work. That is also why the paths here are written out rather than
> built from `$Root`.
<!-- @formatter:on -->

The file is `KEY=VALUE`, one per line, `#` for comments — the same format the systemd unit
reads on the other platform. A `#` inside a value is part of the value, and quotes around a
value are stripped, which is how you write one with trailing spaces. A UTF-8 byte-order
mark, which is what Notepad and PowerShell 5.1 write, is ignored.

It inherits the ACL set in Step 1, so SYSTEM and Administrators can read it and nobody else
can. Check that, because it holds the master key:

```powershell
icacls "$Root\env"
```

<!-- @formatter:off -->
> **`BASE_URL` is load-bearing.** It is the address in the install command handed to each
> new host, and — through `MTLS_HOST`, which defaults to its hostname — the name inside the
> certificate agents pin. Set it to what agents will actually dial before enrolling
> anything. `BASE_URL` and `LISTEN_HTTPS` must carry the same port.
<!-- @formatter:on -->

## Step 5 — Install and start the service

The binary registers itself. There is nothing to write into the registry by hand, and no
service wrapper to download:

```powershell
& "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --service-install `
    --env-file "C:\ProgramData\nsclient-fleet\env"

sc.exe start nsclient-fleet
sc.exe query nsclient-fleet
```

That registers `nsclient-fleet` as an automatic-start service running as **LocalSystem**,
with the env file in its command line and a restart-on-failure policy (three attempts, five
seconds apart) matching the systemd unit's `Restart=on-failure`.

<!-- @formatter:off -->
> **Why the binary installs itself rather than `sc.exe create`.** A service is not just a
> program the SCM launches: within seconds of starting, it has to connect back to the
> service controller, register a handler and report `SERVICE_RUNNING`. A plain console
> program never does, so `sc.exe create` pointed at one produces `The service did not
> respond to the start request in a timely fashion` — which says nothing about the real
> cause. `nsclient-fleet.exe` speaks that protocol, and works out at startup whether it was
> launched by the SCM or from a console, so the same binary and the same command line serve
> either way. `sc.exe create` against it is therefore fine too; `--service-install` just
> also sets the description and the restart policy.
<!-- @formatter:on -->

Check the log — not stdout, which a service has nowhere to write:

```powershell
Get-Content "C:\ProgramData\nsclient-fleet\logs\fleet.log.$(Get-Date -f yyyy-MM-dd)" -Tail 20
```

The first start does a lot, and the log says so:

```
loaded settings from --env-file  vars=["BASE_URL", "DATABASE_PATH", "LISTEN_HTTPS", …]
starting nsclient-fleet          version=0.1.0 on_prem=true
migrations applied               migration_version=13
on-prem admin user created       email=admin@example.internal tenant_id=1
generated and persisted mTLS server cert  path=C:\ProgramData\nsclient-fleet\data\mtls-server.crt
HTTPS listening (certificate from disk)   addr=0.0.0.0:9443 self_signed=true
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

```powershell
# -k because nothing trusts the certificate yet. That is the next step.
curl.exe -k https://localhost:9443/healthz      # → OK
```

`curl.exe` with the extension, so PowerShell runs the curl that ships with Windows rather
than its own `Invoke-WebRequest` alias. `Invoke-WebRequest -SkipCertificateCheck` does the
same thing on PowerShell 7 and does not exist on 5.1.

### Stopping, restarting, removing

```powershell
sc.exe stop nsclient-fleet          # drains, then exits — see "Stopping cleanly" below
sc.exe start nsclient-fleet
& "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --service-uninstall
```

`--service-uninstall` stops the service first and leaves the data directory alone, so it is
the safe way to move an install to a different path or a newer layout.

### Optional: run as a virtual service account instead of LocalSystem

LocalSystem is the Windows equivalent of running as root, and the systemd unit deliberately
runs as a dedicated unprivileged user. The Windows analogue is the service's own virtual
account, which Windows creates and manages for you:

```powershell
icacls "C:\ProgramData\nsclient-fleet" /grant "NT SERVICE\nsclient-fleet:(OI)(CI)F"
sc.exe config nsclient-fleet obj= "NT SERVICE\nsclient-fleet" password= ""
Restart-Service nsclient-fleet
```

Grant the ACL **before** changing the account, and check the log after the restart: a
service that cannot read its own env file or write its database fails at startup, and this
is the step that causes it. To go back, `sc.exe config nsclient-fleet obj= LocalSystem`.

Binding port 9443 needs no privilege either way. A port below 1024 does not either on
Windows — that restriction is a unix one.

## Step 6 — Make the certificate trusted

The generated certificate encrypts the connection, but no browser trusts it, so every visit
costs a click-through — and a warning you click through every day is a warning you will
also click through on the day it means something.

Pick by how many machines you have.

### Option A — distribute the generated certificate

The smallest estates want no CA at all. The server already generated a certificate; install
it as a trusted root on the handful of machines that need to reach the UI:

```powershell
# On the server, hand out the certificate (public — it needs no protection in transit):
Copy-Item "C:\ProgramData\nsclient-fleet\data\web-server.crt" \\share\fleet-web.crt

# On each machine that will open the UI, elevated:
Import-Certificate -FilePath \\share\fleet-web.crt -CertStoreLocation Cert:\LocalMachine\Root
```

It works, and it is the least pleasant to live with: every regeneration is another round of
distribution. Firefox keeps its own trust store and ignores this one.

### Option B — your own internal CA

If you already have an internal CA — AD CS, or anything else — this is a certificate
request like any other, and every machine that already trusts your CA trusts this server
with no per-machine step. Issue one for `BASE_URL`'s hostname.

**The server reads PEM, not PFX**, which is the one thing that catches people here, because
a Windows CA hands you a `.pfx`. Convert it with openssl (from Git for Windows, or
`winget install ShiningLight.OpenSSL.Light`):

```powershell
openssl pkcs12 -in fleet.pfx -out web.pem -nokeys  -clcerts
openssl pkcs12 -in fleet.pfx -out web.key -nocerts -nodes
```

`web.key` must be an unencrypted PKCS#8, PKCS#1 or SEC1 PEM block — that is what `-nodes`
above produces. Then put both under the data directory and swap `TLS_SELF_SIGNED=true` in
the env file for:

```
TLS_CERT=C:\ProgramData\nsclient-fleet\data\web.pem
TLS_KEY=C:\ProgramData\nsclient-fleet\data\web.key
```

```powershell
Restart-Service nsclient-fleet
```

`TLS_CERT`/`TLS_KEY` and `TLS_SELF_SIGNED` are mutually exclusive and the server refuses to
start with both — either it generates the certificate or you supply it, and a deployment
should not have to guess which one it got. If `TLS_CERT` is a chain, put the leaf first and
the intermediates after it, in one file.

### Option C — mkcert, for a lab

[mkcert](https://github.com/FiloSottile/mkcert) is a small local CA that installs its root
into your trust stores for you. `choco install mkcert` or `scoop install mkcert`, then
`mkcert -install` on the machine with the browser, and issue a certificate covering every
name and address you will type in the URL bar:

```powershell
mkcert -cert-file web.pem -key-file web.key fleet.example.internal 10.0.0.42 localhost 127.0.0.1
```

Point `TLS_CERT`/`TLS_KEY` at the result as in Option B. A local CA is trusted for *every*
site on the machine that installed it, so keep its root key off shared storage and move to
Option B once more than a couple of people need the UI.

### Verify

```powershell
$c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 `
       "C:\ProgramData\nsclient-fleet\data\web-server.crt"
$c | Format-List Subject, Issuer, NotAfter
# 2.5.29.17 is the subject alternative name. By OID rather than by friendly name, which is
# localised — on a Swedish Windows the filter below matches nothing if you spell it out.
($c.Extensions | Where-Object { $_.Oid.Value -eq "2.5.29.17" }).Format($true)
```

```
DNS Name=fleet.example.internal
IP Address=10.0.0.42
```

The SAN list must contain the name you are dialling — a certificate for
`fleet.example.internal` is not valid for that machine's IP address. Then load the UI: no
warning, and a padlock.

## Step 7 — Open the firewall

```powershell
New-NetFirewallRule -DisplayName "NSClient Fleet (UI and agents)" `
  -Direction Inbound -Protocol TCP -LocalPort 9443 -Action Allow
```

That is the whole list. One application port carries the UI, the API and every agent;
there is no second port unless you disable TLS, and outbound 587 only matters if you use an
SMTP relay.

<!-- @formatter:off -->
> **Nothing may terminate TLS in front of this.** An inspecting proxy, most L7 load
> balancers, and any reverse proxy that re-encrypts — each of them breaks agent mTLS,
> because agents authenticate with a client certificate against a server certificate they
> pinned. Pass TCP through unmodified, or put the server directly on the network.
<!-- @formatter:on -->

## Step 8 — Sign in and enroll a host

Open `https://fleet.example.internal:9443/` and sign in with `ON_PREM_ADMIN_EMAIL` and the
password you hashed in Step 3.

Then **Hosts → Add host**. The install command it returns carries a one-time bootstrap
token, good for an hour:

```
nscp enroll --server https://fleet.example.internal:9443 --token <bootstrap-token>
```

Run that on the machine you are adding. NSClient++ is a separate product;
[Central management with NSClient Fleet](https://nsclient.org/docs/setup/fleet/) is the
walkthrough from its side — enrolling, trusting this server's certificate, and what changes
on the agent afterwards. What matters on this side:

- **The agent verifies `BASE_URL`'s certificate at enrollment**, against the host's own
  trust store (on Windows, the ROOT store). With a self-signed or internal-CA certificate
  the agent needs `--ca C:\path\to\ca.pem`. This is the one place the web certificate
  matters to an agent; after enrollment it pins the *mTLS* certificate and never consults
  the trust store again.
- **The token is one-time** and is burned on first use. A failed attempt needs a new one.
- **The host appears as pending** until its first poll, then moves to its real status.

The wire contract, if you are implementing an agent rather than using NSClient++, is in
[agent-implementation.md](agent-implementation.md).

## Step 9 — Back up the right four things

```powershell
Stop-Service nsclient-fleet
Compress-Archive -Path "C:\ProgramData\nsclient-fleet\data\*" `
  -DestinationPath "D:\backups\fleet-$(Get-Date -f yyyy-MM-dd).zip"
Start-Service nsclient-fleet
```

That covers the database, the bundles, and both certificates. It does **not** cover
`MASTER_KEY`, and must not: the key belongs somewhere the backup is not, or the encryption
protects nothing. The stop is not optional in this form — SQLite in WAL mode is not safe to
copy file-by-file while it is being written. See
[§9 of deployment.md](deployment.md#9-backups-and-restore) for the hot-copy version that
does not need one.

---

## Producing the hash

`ON_PREM_ADMIN_PASSWORD_HASH` holds an argon2 PHC string — the algorithm, its parameters,
a random salt, and the hash, in one line:

```
$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQAAAAAAAAAAA$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
 └ algorithm └ version └ memory, iterations, parallelism └ salt └ hash
```

It is what the server compares against at sign-in, and it cannot be reversed into the
password, which is the point: the env file lands in backups, in configuration repositories
and in whatever tool deployed it, and a hash there costs an attacker a brute-force run per
guess rather than nothing at all.

`nsclient-fleet --hash-password` produces one. There is no ubiquitous argon2 command-line
tool, and the one packaged on some Linux distributions defaults to parameters this server
does not use — so the binary that checks the hash is also the one that makes it.

**Interactively** (the prompt does not echo, and asks twice):

```powershell
nsclient-fleet.exe --hash-password
```

**From a script or a secret store**, reading one line from stdin:

```powershell
"a strong password" | & "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --hash-password
```

```bash
# Linux, same binary, same flag
printf '%s' "$PASSWORD" | nsclient-fleet --hash-password
```

The explanatory line goes to stderr and the hash to stdout, so redirecting captures the
hash alone:

```powershell
"a strong password" | & nsclient-fleet.exe --hash-password 2>$null | Set-Content hash.txt
```

Each run produces a different string, because the salt is fresh each time. All of them
verify — the salt travels inside the PHC string.

Then quote it in the env file. It contains `$`, which the file itself takes literally, but
a shell that writes the file will not:

```
ON_PREM_ADMIN_PASSWORD_HASH=$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ…
```

`ON_PREM_ADMIN_PASSWORD` takes the plaintext instead, for a deployment that cannot produce
a hash. Setting both is a startup error. Either way the failed-login path is rate-limited,
delayed and logged.

## Stopping cleanly

`sc.exe stop`, a restart and a machine shutdown all reach the same path: the service stops
accepting new connections, finishes the ones in flight (up to 15 seconds), reports
`SERVICE_STOPPED` and exits. In the log:

```
shutdown signal received
shared-port listener draining
shared-port listener stopped  drained=true
stopped
```

Run from a console instead of as a service — which is the fastest way to see a startup
error while you are still setting things up — Ctrl-C, Ctrl-Break and closing the window do
the same thing:

```powershell
& "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --env-file "C:\ProgramData\nsclient-fleet\env"
```

Comment out `LOG_FILE` for that, or the output you are waiting for goes to the file instead
of the console.

---

## Troubleshooting

**The service will not start, and the SCM says nothing useful.** Read the log file, which
is the only place the reason exists. If the service dies before it can open the log — a
bad `LOG_FILE` path, a missing env file — run the same command line from an elevated
console and the error goes to the terminal instead:

```powershell
& "C:\Program Files\nsclient-fleet\nsclient-fleet.exe" --env-file "C:\ProgramData\nsclient-fleet\env"
```

Configuration errors are deliberately fatal and name the variable.

| Message | Cause |
| ------- | ----- |
| `MASTER_KEY required` | Not set, or not 32 bytes of base64 |
| `reading env file …` | The path in the service's command line is wrong, or the service account cannot read it |
| `ON_PREM=true but neither ON_PREM_ADMIN_PASSWORD nor ON_PREM_ADMIN_PASSWORD_HASH is set` | No admin credential; sign-in would fail |
| `ON_PREM_ADMIN_PASSWORD_HASH is not a valid PHC string` | Truncated or re-wrapped hash — it is one line |
| `TLS_CERT and TLS_KEY must be set together` | Only one of the pair |
| `… contains no usable private key` | The key is a PFX or DER, or encrypted — see Step 6 |
| `access denied` from `--service-install` | Not an elevated prompt |

**`--service-install` says the service is already installed.** `--service-uninstall` first,
or change the existing one with `sc.exe config`.

**The service starts, then stops immediately.** Almost always the env file: unreadable by
the service account (check after switching to a virtual service account), or a value the
server refuses. The log names it.

**The browser warns.** Either the issuing CA is not installed where the browser runs, or
the name you typed is not in the certificate's SAN list — Step 6's verify command shows
both. Firefox keeps its own trust store and ignores the system one.

**An agent cannot connect after enrolling.** Almost always something terminating TLS in
between (Step 7), or a changed `MTLS_HOST`. A regenerated mTLS certificate logs loudly:

```
persisted mTLS server cert unusable — regenerating. Agents enrolled against the old
cert cannot connect and must be re-enrolled.
```

Treat that line as an incident, not a note.

**Windows Defender or an EDR quarantines the binary.** It is an unsigned executable that
opens listening sockets. Verify the attestation (Step 2), then add an exclusion for
`C:\Program Files\nsclient-fleet\nsclient-fleet.exe` rather than for the data directory.

---

## Next

- [linux-install.md](linux-install.md) — the same server on Linux, under systemd.
- [docker.md](docker.md) — the same server as a container.
- [deployment.md](deployment.md) — every environment variable, ACME, sizing, the platform
  console.
- [ca-rotation-playbook.md](ca-rotation-playbook.md) — rotating a tenant CA, planned or
  after a compromise.
