#!/usr/bin/env bash
# Enable Wazuh archive logging, persistently.
#
# The collector reads /var/ossec/logs/archives/archives.json — every event, not
# just rule-triggered alerts. That file is only written when <logall_json> is
# yes, and the Wazuh manager image ships it as no.
#
# Patching the RUNNING container does not work. The manager bind-mounts
# /wazuh-config-mount/etc/ossec.conf from the host and its entrypoint copies
# that file over /var/ossec/etc/ossec.conf on every start, so an in-container
# edit is wiped by the very restart needed to apply it. This was previously done
# by hand inside the container, which is why archive logging silently vanished
# whenever the stack was restarted: the lab came up healthy, the agent enrolled,
# and every technique reported NO_TELEMETRY because the archive the collector
# reads was never written.
#
# So: patch the host-side source of the config mount, then restart.
set -euo pipefail

MANAGER="${1:-single-node-wazuh.manager-1}"

if ! docker ps -a --format '{{.Names}}' | grep -qx "$MANAGER"; then
  echo "manager container '$MANAGER' not found" >&2
  exit 1
fi

# Resolve the host path backing the config mount, rather than assuming a layout.
SRC=$(docker inspect "$MANAGER" \
  --format '{{range .Mounts}}{{if eq .Destination "/wazuh-config-mount/etc/ossec.conf"}}{{.Source}}{{end}}{{end}}')

if [ -z "$SRC" ]; then
  echo "no /wazuh-config-mount/etc/ossec.conf mount on $MANAGER" >&2
  echo "this lab layout is unexpected — enable <logall_json> in the manager config by hand" >&2
  exit 1
fi
if [ ! -w "$SRC" ]; then
  echo "config source is not writable: $SRC" >&2
  exit 1
fi

if grep -q '<logall_json>yes</logall_json>' "$SRC"; then
  echo "archive logging already enabled in $SRC"
else
  if ! grep -q '<logall_json>' "$SRC"; then
    echo "no <logall_json> element in $SRC — cannot patch safely" >&2
    exit 1
  fi
  cp "$SRC" "$SRC.bak.$(date +%Y%m%d%H%M%S)"
  sed -i 's|<logall_json>no</logall_json>|<logall_json>yes</logall_json>|' "$SRC"
  echo "enabled <logall_json> in $SRC"
fi

docker restart "$MANAGER" >/dev/null
echo "manager restarted"

# Verify it actually took effect inside the container — the point of this script
# is that the obvious approach silently does not.
for _ in $(seq 1 20); do
  if docker exec "$MANAGER" sh -c "grep -q '<logall_json>yes</logall_json>' /var/ossec/etc/ossec.conf" 2>/dev/null; then
    echo "verified: archive logging active in the manager"
    exit 0
  fi
  sleep 3
done
echo "FAILED: <logall_json> is not yes inside the container after restart" >&2
exit 1
