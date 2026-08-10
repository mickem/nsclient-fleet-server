#!/usr/bin/env bash
# One-shot bootstrap for a fresh VM. Run as root on the target.
#
# Creates the nsclient-fleet user, the install + data layout, drops the systemd unit, and prepares
# /etc/nsclient-fleet/env with placeholders. Edit /etc/nsclient-fleet/env before starting the service.

set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

useradd --system --home-dir /opt/nsclient-fleet --shell /usr/sbin/nologin nsclient-fleet 2>/dev/null || true

install -d -m 755 -o nsclient-fleet -g nsclient-fleet /opt/nsclient-fleet
install -d -m 750 -o nsclient-fleet -g nsclient-fleet /opt/nsclient-fleet/data
install -d -m 750 -o nsclient-fleet -g nsclient-fleet /opt/nsclient-fleet/data/bundles
install -d -m 750 -o nsclient-fleet -g nsclient-fleet /opt/nsclient-fleet/data/acme
install -d -m 750 -o root  -g nsclient-fleet /etc/nsclient-fleet

if [[ ! -f /etc/nsclient-fleet/env ]]; then
  cat > /etc/nsclient-fleet/env <<'TEMPLATE'
# Required
MASTER_KEY=replace-me-with-`openssl rand -base64 32`
BASE_URL=https://app.example.com

# Production HTTPS via Let's Encrypt (TLS-ALPN-01).
# Agent mTLS shares this port — routed by ALPN, so 443 is the only inbound port needed.
# Setting LISTEN_MTLS here would move agents back onto a dedicated port; leave it unset.
ACME_DOMAINS=app.example.com
ACME_CONTACT=admin@example.com
ACME_CACHE_DIR=/opt/nsclient-fleet/data/acme
LISTEN_HTTPS=0.0.0.0:443

# Cookies must be Secure when served over HTTPS
COOKIE_SECURE=true

# DB
DATABASE_PATH=/opt/nsclient-fleet/data/fleet.db

# SMTP for magic links (optional — falls back to stdout when unset)
# SMTP_HOST=smtp.example.com
# SMTP_PORT=587
# SMTP_USER=postmaster@example.com
# SMTP_PASSWORD=...
# SMTP_FROM=NSClient Fleet <noreply@example.com>

# Cloudflare Turnstile on signup (optional)
# TURNSTILE_SECRET=...

# Switch ACME to staging while testing the deploy (avoids LE rate limits)
# ACME_STAGING=true
TEMPLATE
  chmod 640 /etc/nsclient-fleet/env
  chown root:nsclient-fleet /etc/nsclient-fleet/env
  echo "wrote /etc/nsclient-fleet/env — edit it before starting the service"
fi

# The unit file lives next to this script in a checkout, but the documented install is
# `curl … | bash` — there $0 is "bash" and there is no sibling file, so fall back to
# pulling the unit from the same release this script came from.
UNIT_DEST=/etc/systemd/system/nsclient-fleet.service
UNIT_SRC="$(dirname "${BASH_SOURCE[0]:-$0}")/nsclient-fleet.service"
UNIT_URL="${UNIT_URL:-https://github.com/mickem/nsclient-fleet-server/releases/latest/download/nsclient-fleet.service}"

if [[ -f "$UNIT_SRC" ]]; then
  install -m 644 "$UNIT_SRC" "$UNIT_DEST"
else
  echo "fetching unit file from $UNIT_URL"
  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT
  if ! curl -fsSL "$UNIT_URL" -o "$tmp"; then
    echo "bootstrap: could not download the systemd unit from $UNIT_URL" >&2
    echo "  Fetch it manually from the repo and install it at $UNIT_DEST," >&2
    echo "  or re-run with UNIT_URL=<url> pointing at nsclient-fleet.service." >&2
    exit 1
  fi
  install -m 644 "$tmp" "$UNIT_DEST"
fi
systemctl daemon-reload

# Don't enable+start automatically — operator must edit /etc/nsclient-fleet/env first
echo
echo "next steps:"
echo "  1. edit /etc/nsclient-fleet/env"
echo "  2. drop the binary at /opt/nsclient-fleet/nsclient-fleet (chown nsclient-fleet:nsclient-fleet, mode 755)"
echo "  3. systemctl enable --now nsclient-fleet"
echo "  4. journalctl -u nsclient-fleet -f"
