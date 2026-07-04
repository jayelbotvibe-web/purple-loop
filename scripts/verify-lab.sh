#!/usr/bin/env bash
# Binary health check for the lab. Exit 0 only if EVERY gate passes.
# The agent must run this before marking any lab issue done.
set -uo pipefail
cd "$(dirname "$0")/.."
# shellcheck disable=SC1091
. ./versions.env
fail=0
ok(){ echo "  PASS: $1"; }
no(){ echo "  FAIL: $1" >&2; fail=1; }

echo "== verify-lab =="

# 1) indexer cluster health green
health=$(docker exec wazuh.indexer \
  curl -s -k -u REDACTED-ROTATED https://localhost:9200/_cluster/health 2>/dev/null || true)
echo "$health" | grep -q '"status":"green"' && ok "indexer cluster health green" \
  || no "indexer cluster health not green (got: ${health:-none})"

# 2) manager API authenticates
tok=$(docker exec wazuh.manager \
  curl -s -k -u wazuh-wui:MyS3cr37P450r.*- -X POST \
  "https://localhost:55000/security/user/authenticate?raw=true" 2>/dev/null || true)
[ -n "$tok" ] && ok "manager API returned a token" || no "manager API auth failed"

# 3) victim registered as an agent
agents=$(docker exec wazuh.manager /var/ossec/bin/agent_control -l 2>/dev/null || true)
echo "$agents" | grep -qi "victim01" && ok "victim01 registered with manager" \
  || no "victim01 not registered (check enrollment / LAB_NETWORK)"

# 4) telemetry round-trip: fire an event on the victim, look for it
docker exec purpleloop-victim sh -c 'id; whoami' >/dev/null 2>&1 || true
sleep 20
hits=$(docker exec wazuh.manager sh -c \
  'grep -c "victim01" /var/ossec/logs/archives/archives.log 2>/dev/null || echo 0')
[ "${hits:-0}" -gt 0 ] 2>/dev/null && ok "telemetry from victim reached manager" \
  || no "no telemetry from victim yet (enable archives, or wait longer)"

echo "== verify-lab: $( [ $fail -eq 0 ] && echo ALL PASS || echo FAILURES ) =="
exit $fail
