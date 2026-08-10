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

echo "deploy: copying $ARTIFACT to ${VM_USER}@${VM_HOST}"
scp -q "$ARTIFACT" "${VM_USER}@${VM_HOST}:/tmp/nsclient-fleet.new"

ssh "${VM_USER}@${VM_HOST}" bash -s <<EOF
set -euo pipefail
sudo install -o nsclient-fleet -g nsclient-fleet -m 755 /tmp/nsclient-fleet.new ${REMOTE_DIR}/nsclient-fleet
rm -f /tmp/nsclient-fleet.new
sudo systemctl restart nsclient-fleet
sleep 1
sudo systemctl is-active --quiet nsclient-fleet
sudo journalctl -u nsclient-fleet -n 20 --no-pager
EOF

echo "deploy: ok"
