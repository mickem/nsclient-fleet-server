#!/bin/sh
# Container entrypoint for nsclient-fleet.
#
# The binary is configured entirely through environment variables and has no flags, so this
# script does only what a container needs on top of that: pick a sensible TLS mode, refuse
# to start on a configuration that would quietly lose data, and exec the server.
#
# `docker run <image>` serves. Any other argument is executed verbatim:
#   docker run --rm <image> nsclient-fleet --version

set -eu

log() { echo "entrypoint: $*"; }
die() {
    echo "entrypoint: $*" >&2
    exit 1
}

require_master_key() {
    [ -n "${MASTER_KEY:-}" ] && return 0

    # Deliberately not generated here. A key written into /data would sit in the same
    # volume, and the same backup, as the database it encrypts — which makes the
    # encryption decorative. It is also unrecoverable: a container that generated a new
    # one on each start would leave every tenant CA and host override undecryptable, with
    # no error until someone tried to use them.
    cat >&2 <<'EOF'
entrypoint: MASTER_KEY is required and is not set.

It encrypts every tenant CA and host override in the database, and it cannot be
recovered: start with a new one and the existing data is unreadable. Generate it
once, keep a copy somewhere other than this container's volume, and pass it in:

    MASTER_KEY=$(openssl rand -base64 32)
    docker run -e MASTER_KEY="$MASTER_KEY" ...

EOF
    exit 1
}

# Pick the TLS mode from what the operator supplied, and say which one was chosen — the
# difference between "my certificate" and "a generated one" is otherwise only visible as a
# browser warning that looks like a mistake.
configure_tls() {
    if [ -n "${ACME_DOMAINS:-}" ]; then
        log "ACME enabled for ${ACME_DOMAINS} — the name must resolve to this host from the public internet"
        return 0
    fi
    if [ -n "${TLS_CERT:-}" ]; then
        log "serving the certificate at ${TLS_CERT}"
        return 0
    fi
    if [ "${TLS_SELF_SIGNED:-}" = "false" ]; then
        log "TLS disabled (TLS_SELF_SIGNED=false, no ACME_DOMAINS, no TLS_CERT) — serving plain HTTP on ${LISTEN:-0.0.0.0:8080}"
        log "Agents get their own port on ${LISTEN_MTLS:-0.0.0.0:9443}; put a TLS terminator in front of the UI."
        return 0
    fi

    # The container's own default. Without it the only no-DNS option is cleartext, and the
    # sign-in form is exactly the page that should not be served that way.
    export TLS_SELF_SIGNED=true
    log "no ACME_DOMAINS or TLS_CERT — generating a self-signed certificate (browsers will warn until its issuer is trusted)"
}

# BASE_URL is the name in magic links, in the install command agents are given, and — via
# MTLS_HOST — in the SAN of the certificate agents pin. A default that is only correct
# from inside the container is worth one line of warning.
check_base_url() {
    if [ -z "${BASE_URL:-}" ]; then
        https_addr="${LISTEN_HTTPS:-0.0.0.0:8443}"
        export BASE_URL="https://localhost:${https_addr##*:}"
        log "BASE_URL not set, using ${BASE_URL}. Agents and email links need an address"
        log "that resolves from outside this container — set BASE_URL before enrolling anything."
    fi
}

serve() {
    require_master_key
    check_base_url
    configure_tls

    # Session cookies travel over TLS in every mode this script leaves enabled, so mark
    # them Secure unless the operator has explicitly chosen otherwise.
    if [ -z "${COOKIE_SECURE:-}" ] && [ "${TLS_SELF_SIGNED:-}" != "false" ]; then
        export COOKIE_SECURE=true
    fi

    log "starting nsclient-fleet"
    exec nsclient-fleet
}

case "${1:-serve}" in
    serve) serve ;;
    *) exec "$@" ;;
esac
