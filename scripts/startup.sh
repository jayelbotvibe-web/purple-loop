#!/usr/bin/env bash
# Purple Loop — startup script. Run from repo root.
set -euo pipefail
echo "=== Purple Loop Startup ==="

# 1. Host prep
echo "[1/5] Host prep..."
if [ "$(sysctl -n vm.max_map_count)" -lt 262144 ]; then
  echo "  Setting vm.max_map_count=262144 (required for Wazuh indexer)"
  sudo sysctl -w vm.max_map_count=262144 >/dev/null
  echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-purpleloop.conf >/dev/null
fi
echo "  vm.max_map_count=$(sysctl -n vm.max_map_count) ✓"

# 2. Lab up
echo "[2/5] Starting Wazuh lab..."
make lab-up 2>&1 | tail -3
sleep 10
echo "  Containers:"
docker ps --format '  {{.Names}} {{.Status}}'

# 3. Verify
echo "[3/5] Verifying lab..."
make verify 2>&1 | tail -5

# 4. Canary
echo "[4/5] Running pipeline canary..."
make canary 2>&1

# 5. Summary
echo "[5/5] Startup complete."
echo ""
echo "Next steps:"
echo "  1. Power on Windows VM in VMware"
echo "  2. ssh windows-vm@192.168.88.13 hostname  # verify"
echo "  3. Generate arbiter export:"
echo "     hermes -z 'export top 10 alerts...' --profile threatlib"
echo "  4. Run campaign:"
echo "     go run ./cmd/purpleloop run --plan plans/discovery.yml --output report.html"
echo ""
echo "Shutdown: make lab-down"
