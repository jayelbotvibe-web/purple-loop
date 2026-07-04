#!/usr/bin/env bash
# Purple Loop — snapshot lab state for fast restore. Run from repo root.
set -euo pipefail
SNAPSHOT_TAG="purpleloop-$(date +%Y%m%d)"

echo "=== Snapshot: $SNAPSHOT_TAG ==="

# Docker containers
for c in single-node-wazuh.manager-1 single-node-wazuh.indexer-1 single-node-wazuh.dashboard-1 purpleloop-victim; do
  img="purpleloop/${c}:${SNAPSHOT_TAG}"
  echo "  $c → $img"
  docker commit "$c" "$img" >/dev/null
done
echo "Docker snapshots created."
echo ""
echo "=== Save to disk ==="
mkdir -p lab/snapshots/
docker save purpleloop/single-node-wazuh.manager-1:${SNAPSHOT_TAG} purpleloop/single-node-wazuh.indexer-1:${SNAPSHOT_TAG} purpleloop/single-node-wazuh.dashboard-1:${SNAPSHOT_TAG} purpleloop/purpleloop-victim:${SNAPSHOT_TAG} | gzip > "lab/snapshots/${SNAPSHOT_TAG}.tar.gz" 2>/dev/null &
PID=$!
echo "  Saving in background (PID $PID)..."
echo ""
echo "=== Windows VM ==="
echo "  Manual step: In VMware → VM → Snapshot → Take Snapshot"
echo "  Name: $SNAPSHOT_TAG"
echo ""
echo "Done. Restore with: bash scripts/restore.sh $SNAPSHOT_TAG"
