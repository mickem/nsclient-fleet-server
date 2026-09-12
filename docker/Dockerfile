# syntax=docker/dockerfile:1

# nsclient-fleet in a container.
#
# The image installs the released musl binary rather than building from source. That binary
# is fully static and already carries the frontend (rust-embed bakes web/dist into it), so
# the runtime layer is the binary, a CA bundle and nothing else — and the thing running in
# the container is bit-for-bit what a VM install would run.
#
# Build:
#   docker build --build-arg FLEET_VERSION=0.1.0 -t nsclient-fleet:0.1.0 docker
#
# The release publishes SHA256SUMS, so the download is verified against it by default;
# FLEET_SKIP_VERIFY=true is the escape hatch for a release that predates it.

ARG ALPINE_VERSION=3.20

# ---------------------------------------------------------------------------
# Fetch and verify in a throwaway stage, so curl never reaches the runtime image.
# ---------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION} AS fetch

ARG FLEET_VERSION
ARG FLEET_BINARY_URL=""
ARG FLEET_SKIP_VERIFY=false
# Which repository's releases to download from. Parameterised so a fork builds its own
# binaries rather than silently pulling upstream's; the publish workflow passes
# github.repository.
ARG FLEET_REPO=mickem/nsclient-fleet-server
# Supplied by buildx: amd64 / arm64.
ARG TARGETARCH

RUN apk add --no-cache ca-certificates curl

RUN set -eu; \
    if [ -z "${FLEET_VERSION}" ] && [ -z "${FLEET_BINARY_URL}" ]; then \
      echo "Set --build-arg FLEET_VERSION=<version> (or FLEET_BINARY_URL=<url>)." >&2; \
      exit 1; \
    fi; \
    case "${TARGETARCH}" in \
      amd64) target="x86_64-unknown-linux-musl" ;; \
      arm64) target="aarch64-unknown-linux-musl" ;; \
      *) echo "No musl release for TARGETARCH=${TARGETARCH}." >&2; exit 1 ;; \
    esac; \
    base="https://github.com/${FLEET_REPO}/releases/download/v${FLEET_VERSION}"; \
    asset="nsclient-fleet-${target}"; \
    url="${FLEET_BINARY_URL:-${base}/${asset}}"; \
    echo "Fetching ${url}"; \
    curl -fsSL --retry 3 --retry-delay 5 -o /tmp/nsclient-fleet "${url}"; \
    if [ "${FLEET_SKIP_VERIFY}" = "true" ] || [ -n "${FLEET_BINARY_URL}" ]; then \
      echo "WARNING: checksum verification skipped." >&2; \
    else \
      curl -fsSL --retry 3 -o /tmp/SHA256SUMS "${base}/SHA256SUMS"; \
      # The release lists every target in one file; check only the line for ours, so a
      # missing sibling asset cannot fail an otherwise valid build.
      ( cd /tmp && cp nsclient-fleet "${asset}" \
        && grep " ${asset}\$" SHA256SUMS | sha256sum -c - \
        && rm -f "${asset}" ); \
    fi; \
    chmod 0755 /tmp/nsclient-fleet; \
    /tmp/nsclient-fleet --version

# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM alpine:${ALPINE_VERSION}

ARG FLEET_VERSION

LABEL org.opencontainers.image.title="nsclient-fleet" \
      org.opencontainers.image.description="NSClient Fleet control plane" \
      org.opencontainers.image.source="https://github.com/mickem/nsclient-fleet-server" \
      org.opencontainers.image.documentation="https://github.com/mickem/nsclient-fleet-server/blob/main/docs/docker.md" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0" \
      org.opencontainers.image.version="${FLEET_VERSION}"

# ca-certificates is for outbound TLS — the SMTP relay, and Let's Encrypt when ACME is on.
# tini reaps the zombies a PID 1 would otherwise accumulate and forwards signals, so
# `docker stop` is a clean shutdown rather than a ten-second wait and a kill.
RUN apk add --no-cache ca-certificates tini \
 && addgroup -S -g 10001 fleet \
 && adduser -S -u 10001 -G fleet -H -s /sbin/nologin fleet \
 && mkdir -p /data \
 && chown fleet:fleet /data

COPY --from=fetch /tmp/nsclient-fleet /usr/local/bin/nsclient-fleet
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

# Everything that must outlive the container: the SQLite database, uploaded bundles, the
# ACME cache, and both server certificates. Losing data/mtls-server.key strands every
# enrolled agent, so this is not an optional convenience — name the volume.
ENV DATABASE_PATH=/data/fleet.db \
    BUNDLE_DIR=/data/bundles \
    ACME_CACHE_DIR=/data/acme \
    MTLS_STATE_DIR=/data \
    TLS_STATE_DIR=/data \
    LISTEN_HTTPS=0.0.0.0:9443 \
    LISTEN=0.0.0.0:8080
VOLUME ["/data"]

# Unprivileged: nothing here needs root, and 9443 is above the privileged range precisely
# so it does not have to. Not 8443: that is the NSClient++ web UI, and a server sharing a
# host with an agent would collide with it. 9443 is also the port agents get in plain-HTTP
# mode (LISTEN_MTLS), so agents dial 9443 whichever way the container runs. Publish it as
# :443 on the host if you want the standard port — BASE_URL's port is what agents are told
# to dial, so any mapping works as long as BASE_URL matches it.
USER fleet:fleet
EXPOSE 9443

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/entrypoint.sh"]
CMD ["serve"]
