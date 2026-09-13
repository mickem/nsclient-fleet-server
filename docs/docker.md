# Running nsclient-fleet in Docker

The whole control plane is one static binary with the frontend, SQLite and TLS termination
inside it, so the container is that binary on Alpine and nothing else. No database
container, no reverse proxy, no sidecar.

For the same thing installed on the host under systemd, see
[linux-install.md](linux-install.md). Everything there about certificates, `BASE_URL` and
backups applies here too — only the packaging differs.

---

## Starting it

`MASTER_KEY` comes first, on its own, because it is the one value you cannot recreate. It
encrypts every tenant CA and every host override; a container started with a different one
cannot read the data in the volume it just mounted, and there is no recovery. Generate it
once and store it somewhere you will still have it in a year.

```bash
MASTER_KEY=$(openssl rand -base64 32)   # once — then put it in a password manager
```

Then start the container with it:

```bash
docker run -d --name nsclient-fleet --restart unless-stopped \
  -e MASTER_KEY="$MASTER_KEY" \
  -e BASE_URL="https://fleet.example.internal:9443" \
  -e ON_PREM=true \
  -e ON_PREM_ADMIN_EMAIL=admin@example.internal \
  -e ON_PREM_ADMIN_PASSWORD_HASH='<argon2 PHC string>' \
  -v fleet-data:/data \
  -p 9443:9443 \
  ghcr.io/mickem/nsclient-fleet:latest
```

That starts a single-tenant install with a self-signed certificate it generates on first
start, signs you in by password, and serves the UI and agent mTLS on one port. Open
`https://fleet.example.internal:9443/` — your browser will warn about the certificate until
you do [TLS](#tls) below.

`ON_PREM_ADMIN_PASSWORD_HASH` takes an argon2 PHC string, which is what to use here —
`docker run` arguments land in the shell history, the process list and `docker inspect`.
The image produces one for you:

```bash
# Interactively — prompts twice, without echoing:
docker run --rm -it ghcr.io/mickem/nsclient-fleet:latest nsclient-fleet --hash-password

# Or from a script or a secret store, one line on stdin:
echo 'a strong password' | \
  docker run --rm -i ghcr.io/mickem/nsclient-fleet:latest nsclient-fleet --hash-password
```

The binary's name is repeated on purpose: the entrypoint serves when given no arguments and
runs anything else verbatim. The hash goes to stdout and the explanatory line to stderr, so
a redirect captures the hash alone. `ON_PREM_ADMIN_PASSWORD` takes the plaintext instead; setting both
is a startup error. Either way the failed-login path is rate-limited, delayed and logged.

<!-- @formatter:off -->
> The container refuses to start without `MASTER_KEY` rather than generating one into
> `/data` — a key sitting in the same volume, and the same backup, as the database it
> encrypts is not protecting much.
<!-- @formatter:on -->

## What is in the image

| | |
| --- | --- |
| Base | `alpine`, pinned by digest, plus `ca-certificates` and `tini` |
| Binary | The released `*-unknown-linux-musl` build, verified against the release's `SHA256SUMS` at build time |
| User | `fleet` (uid 10001), non-root |
| Port | 9443 — above the privileged range so root is not needed, and not 8443, which the NSClient++ web UI already uses |
| Volume | `/data` |
| Health | `HEALTHCHECK` hits `/healthz`, which answers only once the database is reachable |

`amd64` and `arm64` are published under the same tag. Pin `:<version>` in production;
`:latest` follows the most recent non-prerelease.

The frontend is compiled into the binary (`rust-embed`), so the container serves the UI
with no outbound access and no asset volume.

## `/data` is the whole of the state

```
/data/fleet.db            SQLite, WAL mode
/data/bundles/            uploaded configuration bundles
/data/acme/               ACME account key + issued certificates (when ACME is on)
/data/web-server.crt/.key the browser certificate, when self-signed
/data/mtls-server.crt/.key the certificate every enrolled agent pins
```

<!-- @formatter:off -->
> **Name the volume.** `mtls-server.key` is unrecoverable in the strict sense: agents pin
> that certificate, and renewal itself requires a working mTLS session, so losing it
> strands the fleet with no remote recovery. An anonymous volume that gets pruned takes it
> with it.
<!-- @formatter:on -->

Back it up the way you would any other volume — with the container stopped, or with
SQLite's own backup command:

```bash
docker run --rm -v fleet-data:/data -v "$PWD:/backup" alpine \
  tar czf /backup/fleet-$(date +%F).tgz -C /data .
```

That archive contains both private keys and the database. It does not contain `MASTER_KEY`,
and should not.

## TLS

Three modes. The container picks one from what you set and says which in its first log
line, because otherwise the difference only shows up as a browser warning that looks like a
mistake.

### Self-signed (the default)

Nothing to set. On first start the server issues itself a certificate covering `BASE_URL`'s
hostname plus `localhost`, `127.0.0.1` and `::1`, and persists it to `/data`, so it is
stable across restarts and any browser exception you grant keeps working.

Override the names with `TLS_HOSTS`:

```bash
-e TLS_HOSTS="fleet.example.internal,10.0.0.42,localhost"
```

To make it actually trusted, use your own certificate below — or follow
[Step 6 of the Linux guide](linux-install.md#step-6--make-the-certificate-trusted), which is
the same problem and the same answers.

### Your own certificate

```bash
docker run -d --name nsclient-fleet --restart unless-stopped \
  -e MASTER_KEY="$MASTER_KEY" \
  -e BASE_URL="https://fleet.example.internal:9443" \
  -e TLS_CERT=/certs/fleet.pem -e TLS_KEY=/certs/fleet.key \
  -v /etc/ssl/fleet:/certs:ro \
  -v fleet-data:/data -p 9443:9443 \
  ghcr.io/mickem/nsclient-fleet:latest
```

The files must be readable by uid 10001. The certificate is read once at startup, so
renewing it means `docker restart nsclient-fleet`.

### Let's Encrypt

For a publicly resolvable name with inbound 443 from the internet:

```bash
  -e ACME_DOMAINS=fleet.example.com -e ACME_CONTACT=ops@example.com \
  -p 443:9443
```

Issuance is TLS-ALPN-01 on the same port — no `:80` listener. Keep `/data` so the ACME
cache survives restarts, or you will re-issue and hit rate limits. `ACME_DOMAINS` with
`TLS_CERT` or `TLS_SELF_SIGNED` is refused at startup: one listener, one certificate
source.

## One port, two protocols

The published port carries the operator UI *and* agent mTLS. They are told apart by ALPN in
the ClientHello, not by port number, which is what lets an agent behind a restrictive
egress filter reach the server on 443 like anything else.

The practical consequence for a container deployment: **nothing may terminate TLS in
front of it.** An ingress controller doing TLS, a reverse proxy, a service mesh sidecar —
each breaks agent mTLS. Publish the port directly, or pass TCP through unmodified.

### Choosing the port

The container listens on 9443. It is deliberately not 8443, which the NSClient++ web UI
already uses: a server sharing a host with an agent would collide with it. To publish on a
different port, change the mapping **and `BASE_URL` together** — the port in `BASE_URL` is
what agents are told to dial, so the two must agree:

```bash
  -e BASE_URL="https://fleet.example.com" -p 443:9443              # standard port
  -e BASE_URL="https://fleet.example.internal:10443" -p 10443:9443
```

The container stays unprivileged either way. `LISTEN_HTTPS` changes the port *inside* the
container, which only matters with `--network host`. When even `BASE_URL` is not the
address agents can reach — a NAT or port forward in front of the host, say — set `MTLS_URL`
to the one they can.

## Compose

```yaml
services:
  fleet:
    image: ghcr.io/mickem/nsclient-fleet:latest
    container_name: nsclient-fleet
    restart: unless-stopped
    environment:
      MASTER_KEY: ${MASTER_KEY:?set MASTER_KEY in .env}
      BASE_URL: https://fleet.example.internal:9443
      ON_PREM: "true"
      ON_PREM_ADMIN_EMAIL: admin@example.internal
      ON_PREM_ADMIN_PASSWORD: ${ADMIN_PASSWORD:?set ADMIN_PASSWORD in .env}
    ports:
      - "9443:9443"
    volumes:
      - fleet-data:/data

volumes:
  fleet-data:
```

```bash
printf 'MASTER_KEY=%s\nADMIN_PASSWORD=%s\n' "$(openssl rand -base64 32)" 'a strong password' > .env
docker compose up -d
```

The file ships in the repository at
[`docker/docker-compose.yml`](../docker/docker-compose.yml). Keep the `.env` — it is the
only copy of the master key.

## Configuration

Every variable in [deployment.md §5](deployment.md#5-environment-reference) works here
unchanged; these are the ones the image sets or interprets differently:

| Variable | In this image | Notes |
| -------- | ------------- | ----- |
| `DATABASE_PATH` | `/data/fleet.db` | |
| `BUNDLE_DIR` | `/data/bundles` | |
| `ACME_CACHE_DIR` | `/data/acme` | |
| `MTLS_STATE_DIR` / `TLS_STATE_DIR` | `/data` | Where the two certificates live |
| `LISTEN_HTTPS` | `0.0.0.0:9443` | Unprivileged by default |
| `TLS_SELF_SIGNED` | `true` unless `ACME_DOMAINS` or `TLS_CERT` is set | Set `false` for plain HTTP on `LISTEN` |
| `COOKIE_SECURE` | `true` whenever TLS is on | Set explicitly to override |
| `BASE_URL` | warns if unset | Defaults to `https://localhost:9443`, which nothing outside the container can reach |
| `MASTER_KEY` | **required** | No default, by design |

### Running one-off commands

Any argument other than `serve` is executed instead of the server:

```bash
docker run --rm ghcr.io/mickem/nsclient-fleet:latest nsclient-fleet --version
docker run --rm ghcr.io/mickem/nsclient-fleet:latest nsclient-fleet --help
```

## Upgrading

```bash
docker pull ghcr.io/mickem/nsclient-fleet:0.2.0
docker rm -f nsclient-fleet
docker run -d ... ghcr.io/mickem/nsclient-fleet:0.2.0    # same MASTER_KEY, same volume
```

Migrations run at startup and are logged (`migrations applied version=N`). The volume
carries the database, both certificates and the bundles across, so agents see the same
server with the same pinned certificate and nothing re-enrolls.

## Building it yourself

```bash
docker build --build-arg FLEET_VERSION=0.1.0 -t nsclient-fleet:0.1.0 docker
```

| Build argument | Default | Notes |
| -------------- | ------- | ----- |
| `FLEET_VERSION` | — | Required. Release version without the `v` prefix |
| `FLEET_REPO` | `mickem/nsclient-fleet-server` | Which repository's releases to download from |
| `FLEET_BINARY_URL` | derived | A specific binary, for testing an unreleased build |
| `FLEET_SKIP_VERIFY` | `false` | Skips the `SHA256SUMS` check |
| `ALPINE_VERSION` | `3.20` | |

The build downloads the release asset and verifies it against the release's `SHA256SUMS`;
it does not compile anything, so what runs in the container is the same binary a VM install
would run.

## How the published image is built

`.github/workflows/publish-docker.yml` builds `linux/amd64` and `linux/arm64` and pushes to
`ghcr.io/<owner>/nsclient-fleet` when a **release is published**. It deliberately does not
trigger on the release workflow: every push to main produces a *draft* release candidate,
and a draft has no downloadable assets for the Dockerfile to fetch. Publishing is the
moment those URLs start resolving.

A release candidate is a prerelease, so it is tagged with its version but never moves
`latest`.

After the build, the workflow pulls the image back out of the registry and checks
`nsclient-fleet --version` against the version it meant to publish — a push that produced
the wrong binary fails the run rather than sitting in the registry.

Run it from the Actions tab against any published tag to rebuild, or with **push**
unticked as a rehearsal that builds both architectures and publishes nothing.

<!-- @formatter:off -->
> **First publish only.** GHCR creates the package **private**, even from a public
> repository, so the `docker run` on this page will fail for everyone until the package's
> visibility is changed to public — once, by hand, under the package's settings. Worth
> doing a manual run against an existing tag first, so the package exists and can be made
> public before a real release depends on it.
<!-- @formatter:on -->

## Enrolling agents against it

Agents verify this server's certificate on the enrollment call, against their own CA
bundle — so a self-signed certificate means each agent needs `--ca` pointing at a copy:

```bash
docker cp nsclient-fleet:/data/web-server.crt ./fleet-ca.pem
# then, on the agent
nscp enroll --server https://fleet.example.internal:9443 --token <token> --ca fleet-ca.pem
```

[Central management with NSClient Fleet](https://nsclient.org/docs/setup/fleet/) walks the
whole thing from the agent's side.

## Troubleshooting

**`MASTER_KEY is required and is not set`** — see the one-liner above. The message is the
whole explanation.

**The container starts, but nothing is reachable.** Check the port mapping matches
`LISTEN_HTTPS` (9443 inside the container, whatever you published outside), and that
`BASE_URL` names an address that resolves from outside the container — the log warns when
it fell back to `localhost`.

**Agents enroll, then fail to connect on a port nobody listens on.** The port in `BASE_URL`
does not match the one you published: agents are told to dial `BASE_URL`'s port. Fix
`BASE_URL` (or set `MTLS_URL`) and re-enroll the affected hosts.

**Agents enroll but never poll.** Something is terminating TLS in front of the container,
or `BASE_URL` changed after they enrolled. See
[§4 of deployment.md](deployment.md#4-certificates--two-of-them-two-trust-models).

**Permission denied on `/data`.** A bind mount (`-v /srv/fleet:/data`) keeps the host's
ownership rather than the image's, and the server runs as uid 10001:

```bash
sudo chown -R 10001:10001 /srv/fleet
```

Named volumes inherit the image's ownership and need no such step, which is why they are
what this page uses.
