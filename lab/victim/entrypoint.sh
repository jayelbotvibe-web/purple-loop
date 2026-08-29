#!/usr/bin/env bash
# Start the telemetry sources and the Wazuh agent, then hold the container open.
#
# Telemetry status is reported LOUDLY at start-up. This used to run
#   service auditd start || auditd || true
# which swallowed every failure, so the container came up looking healthy with
# no process-creation source at all. The pipeline then reported NO_TELEMETRY for
# every technique, which reads as a detection problem and is not one — it is a
# victim that never had the telemetry to begin with.
set -u
: "${WAZUH_MANAGER:=wazuh.manager}"
: "${WAZUH_AGENT_NAME:=victim01}"

banner() { echo "[victim] $*"; }

# Point the agent at the manager.
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
  /var/ossec/etc/ossec.conf || banner "WARNING: could not set manager address"

# --- process-creation telemetry ---------------------------------------------
# auditd needs the kernel audit subsystem. It is unavailable in many
# environments (kernel built without it, audit locked, or the netlink interface
# refused) and there is no point pretending otherwise: say so once, clearly,
# rather than failing silently.
PROCESS_TELEMETRY="none"
if auditctl -s >/dev/null 2>&1; then
  if service auditd start >/dev/null 2>&1 || auditd >/dev/null 2>&1; then
    # Capture execve so events carry Image and CommandLine, which is what the
    # evaluator's process_creation rules require.
    auditctl -a always,exit -F arch=b64 -S execve -k purpleloop_exec >/dev/null 2>&1
    auditctl -a always,exit -F arch=b32 -S execve -k purpleloop_exec >/dev/null 2>&1
    PROCESS_TELEMETRY="auditd"
    banner "process-creation telemetry: auditd (execve rules loaded)"
  else
    banner "WARNING: kernel audit is available but auditd failed to start"
  fi
else
  banner "WARNING: kernel audit subsystem unavailable — auditctl cannot talk to it."
  banner "WARNING: this victim has NO process-creation telemetry."
  banner "WARNING: the pipeline canary cannot fire, so runs will be INCONCLUSIVE."
  banner "WARNING: this is a lab capability gap, NOT a detection gap."
  banner "WARNING: see docs/PITFALLS.md for what was measured and why a VM is the fix."
fi

/var/ossec/bin/wazuh-control start || banner "WARNING: wazuh-agent failed to start"

banner "agent=${WAZUH_AGENT_NAME} manager=${WAZUH_MANAGER} process_telemetry=${PROCESS_TELEMETRY}"

# Tail the agent log so `docker logs` is useful; keep PID 1 alive.
touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
