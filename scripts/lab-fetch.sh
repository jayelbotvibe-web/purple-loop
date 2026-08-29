#!/usr/bin/env bash
# Fetch the pinned official Wazuh single-node deployment + Atomic Red Team,
# and lay our override into place. Vendored dirs are gitignored.
set -euo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. ./versions.env

dest=lab/wazuh-docker
if [ ! -d "$dest" ]; then
  echo "cloning wazuh-docker @ ${WAZUH_DOCKER_REF}"
  git clone --depth 1 --branch "${WAZUH_DOCKER_REF}" https://github.com/wazuh/wazuh-docker.git "$dest"
else
  echo "wazuh-docker already present ($dest)"
fi

# lay our override beside the base compose so Compose auto-merges it
cp lab/docker-compose.override.yml "$dest/single-node/docker-compose.override.yml"
cp lab/victim/entrypoint.sh lab/victim/entrypoint.sh 2>/dev/null || true
echo "override installed into $dest/single-node/"

# Vendor Atomic Red Team at the RECORDED commit. This used to clone HEAD and
# then overwrite the pin file with whatever it got, so the "pin" tracked
# upstream instead of holding it — every re-clone could silently change the
# commands the engine executes. scripts/fetch-atomics.sh checks out the
# recorded commit and verifies it.
bash scripts/fetch-atomics.sh

# generate certs (official helper) if not already present
if [ ! -f "$dest/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
  echo "generating certs via official generator…"
  ( cd "$dest/single-node" && docker compose -f generate-indexer-certs.yml run --rm generator )
fi
echo "== lab fetch done =="
