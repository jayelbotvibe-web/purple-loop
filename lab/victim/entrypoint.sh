#!/usr/bin/env bash
# Start auditd and the Wazuh agent (auto-enrolling against $WAZUH_MANAGER),
# then hold the container open.
set -e
: "${WAZUH_MANAGER:=wazuh.manager}"
: "${WAZUH_AGENT_NAME:=victim01}"

# point the agent at the manager
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" /var/ossec/etc/ossec.conf || true

service auditd start || auditd || true
/var/ossec/bin/wazuh-control start || true

# tail agent log so `docker logs` is useful; keep PID 1 alive
touch /var/ossec/logs/ossec.log
exec tail -F /var/ossec/logs/ossec.log
