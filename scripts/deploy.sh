#!/usr/bin/env bash
# Push a freshly-built nsclient-fleet binary to a VM and restart the service.
#
# Required env:
#   VM_HOST     SSH-reachable hostname or IP of the VM
# Optional env:
#   VM_USER     SSH user (default: deploy)
#   ARTIFACT    path to the binary (default: target/aarch64-unknown-linux-musl/release/nsclient-fleet)
#   REMOTE_DIR  install directory on the VM (default: /opt/nsclient-fleet)

set -euo pipefail

VM_HOST="${VM_HOST:?VM_HOST not set}"
VM_USER="${VM_USER:-deploy}"
ARTIFACT="${ARTIFACT:-target/aarch64-unknown-linux-musl/release/nsclient-fleet}"
REMOTE_DIR="${REMOTE_DIR:-/opt/nsclient-fleet}"

if [[ ! -f "$ARTIFACT" ]]; then
  echo "deploy: artifact not found at $ARTIFACT" >&2
  echo "  Build first with: cross build --release --target aarch64-unknown-linux-musl --bin nsclient-fleet" >&2
  exit 1
fi

# Staged in a private directory, not at a fixed /tmp path. `/tmp` is world-writable and
# sticky, so another local account could pre-create /tmp/nsclient-fleet.new and win the
# race, or swap its contents between the copy landing and the install running it as root.
# `mktemp -d` gives a 0700 directory with an unpredictable name, which closes both.
STAGE=$(ssh "${VM_USER}@${VM_HOST}" 'mktemp -d')
if [[ -z "$STAGE" ]]; then
  echo "deploy: could not create a staging directory on ${VM_HOST}" >&2
  exit 1
fi

echo "deploy: copying $ARTIFACT to ${VM_USER}@${VM_HOST}:${STAGE}"
scp -q "$ARTIFACT" "${VM_USER}@${VM_HOST}:${STAGE}/nsclient-fleet.new"

# What we sent, so the remote side can confirm it is installing that and not something else.
EXPECTED=$(sha256sum "$ARTIFACT" | cut -d' ' -f1)

ssh "${VM_USER}@${VM_HOST}" bash -s <<EOF
set -euo pipefail
trap 'rm -rf ${STAGE}' EXIT

actual=\$(sha256sum ${STAGE}/nsclient-fleet.new | cut -d' ' -f1)
if [[ "\$actual" != "${EXPECTED}" ]]; then
  echo "deploy: staged binary does not match what was sent (\$actual != ${EXPECTED})" >&2
  exit 1
fi

# root-owned: the service must not be able to rewrite its own executable. ProtectSystem=strict
# already makes /opt read-only to it, but ownership costs nothing and does not depend on the
# unit staying as it is.
sudo install -o root -g root -m 755 ${STAGE}/nsclient-fleet.new ${REMOTE_DIR}/nsclient-fleet
sudo systemctl restart nsclient-fleet
sleep 1
sudo systemctl is-active --quiet nsclient-fleet
sudo journalctl -u nsclient-fleet -n 20 --no-pager
EOF

echo "deploy: ok"
