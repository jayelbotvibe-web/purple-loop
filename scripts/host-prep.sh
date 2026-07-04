#!/usr/bin/env bash
# Prepare the host for the Wazuh lab. Idempotent. Safe to re-run.
# The ONLY host-level change is vm.max_map_count (required by the indexer).
set -euo pipefail

need=262144
echo "== Purple Loop host prep =="

# 1) vm.max_map_count — indexer will not start without this
cur=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "$cur" -lt "$need" ]; then
  echo "vm.max_map_count is $cur; raising to $need"
  sudo sysctl -w vm.max_map_count=$need
  echo "vm.max_map_count=$need" | sudo tee /etc/sysctl.d/99-purpleloop.conf >/dev/null
else
  echo "vm.max_map_count OK ($cur)"
fi

# 2) tooling present?
for bin in docker git go; do
  if command -v "$bin" >/dev/null 2>&1; then echo "found: $bin"; else echo "MISSING: $bin" >&2; fi
done
if docker compose version >/dev/null 2>&1; then echo "found: docker compose"; else echo "MISSING: docker compose" >&2; fi

# 3) resource sanity (warn only)
mem_gb=$(awk '/MemTotal/{printf "%.0f", $2/1024/1024}' /proc/meminfo)
free_gb=$(df -Pk . | awk 'NR==2{printf "%.0f", $4/1024/1024}')
echo "RAM: ${mem_gb}GB total | Disk free here: ${free_gb}GB"
[ "$mem_gb" -lt 16 ] && echo "WARN: <16GB RAM — close other VMs before a full campaign" >&2 || true
[ "$free_gb" -lt 60 ] && echo "WARN: <60GB free — indexer + images need headroom" >&2 || true

echo "== host prep done =="
