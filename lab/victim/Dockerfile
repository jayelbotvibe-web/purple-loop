# Ubuntu victim: the Wazuh agent plus whatever process-creation telemetry this
# host can actually provide.
#
# NOT privileged, and NOT running Sysmon for Linux. That was tried and measured
# — see docs/PITFALLS.md, "Why the Linux victim is not a container with Sysmon".
# Sysmon works, but its eBPF is kernel-global: inside a container it observes
# every process on the host, and the event carries no container identity. Scoping
# it after the fact by resolving host PIDs is defeated by PID reuse, which let
# host binaries through; verifying process identity closes that leak but then
# drops the short-lived processes the atomics actually spawn. Either way the
# telemetry is wrong in a direction this project refuses to ship.
#
# The Linux equivalent of the Windows victim is a VM, not a container.
FROM ubuntu:22.04

ARG WAZUH_VERSION=4.9.2
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
      curl gnupg lsb-release auditd audispd-plugins procps ca-certificates \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
        | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && apt-get install -y wazuh-agent=${WAZUH_VERSION}-1 \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
