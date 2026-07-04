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

# pin Atomic Red Team and record the commit for reproducibility
art=lab/atomic-red-team
if [ ! -d "$art" ]; then
  git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git "$art"
fi
( cd "$art" && git rev-parse HEAD ) > mappings/atomic-red-team.commit
echo "atomic-red-team pinned at $(cat mappings/atomic-red-team.commit)"

# generate certs (official helper) if not already present
if [ ! -f "$dest/single-node/config/wazuh_indexer_ssl_certs/root-ca.pem" ]; then
  echo "generating certs via official generator…"
  ( cd "$dest/single-node" && docker compose -f generate-indexer-certs.yml run --rm generator )
fi
echo "== lab fetch done =="
