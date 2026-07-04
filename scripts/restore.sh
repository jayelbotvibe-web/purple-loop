#!/usr/bin/env bash
# Purple Loop — restore lab from snapshot. Usage: bash scripts/restore.sh <tag>
set -euo pipefail
TAG="${1:-}"
if [ -z "$TAG" ]; then
  echo "Usage: bash scripts/restore.sh <snapshot-tag>"
  echo "Available snapshots:"
  ls lab/snapshots/*.tar.gz 2>/dev/null | sed 's|.*/||;s|\.tar\.gz||' || echo "  (none)"
  exit 1
fi

SNAPSHOT="lab/snapshots/${TAG}.tar.gz"
if [ ! -f "$SNAPSHOT" ]; then
  echo "Snapshot not found: $SNAPSHOT"
  exit 1
fi

echo "=== Restoring from $TAG ==="

# Stop current
make lab-down 2>/dev/null || true

# Load images
echo "  Loading images..."
docker load < "$SNAPSHOT"

# Tag as latest and restart
for c in single-node-wazuh.manager-1 single-node-wazuh.indexer-1 single-node-wazuh.dashboard-1 purpleloop-victim; do
  docker tag "purpleloop/${c}:${TAG}" "purpleloop/${c}:latest" 2>/dev/null || true
done

make lab-up
echo "=== Lab restored. Run 'make verify' to confirm. ==="
