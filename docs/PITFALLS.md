# Pitfalls & fixes

Check here before debugging.

## Wazuh indexer won't start / exits immediately
- **Cause:** `vm.max_map_count` too low. **Fix:** `scripts/host-prep.sh` (sets it to 262144).
- **Cause:** JVM heap too large for the box. **Fix:** heap is pinned to `-Xms4g -Xmx4g` in the
  override; don't raise it on this machine.

## Indexer cluster health not green (yellow/red)
- Single-node → replicas can't allocate. Yellow is often acceptable for a lab; verify-lab treats
  only **green** as pass, so if it stays yellow, set index replicas to 0 in the indexer config and
  retry. Record the change in PROGRESS.md.

## Dashboard shows 503 / "server not ready"
- The dashboard raced the indexer. Wait 60-90s after `lab-up`; it resolves once the indexer is up.
  Not a failure — re-run `make verify`.

## Victim not registered / no telemetry
- **Cause:** wrong network — the victim can't reach `wazuh.manager`. **Fix:** confirm `LAB_NETWORK`
  in `versions.env` matches `docker network ls`; the victim must be on the stack's network.
- **Cause:** enrollment needs the manager's authd password. **Fix:** check `docker logs
  purpleloop-victim` for enrollment errors; enable password enrollment or register manually with
  `agent-auth`.
- **Cause:** archives logging disabled, so the round-trip check finds nothing. **Fix:** enable
  `<logall_json>yes</logall_json>` in the manager config for lab use.

## Certs errors on lab-up
- The generator didn't run or ran against a different ref. **Fix:** delete
  `lab/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/` and re-run `scripts/lab-fetch.sh`.

## `go build` fails after adding a dep
- Run `go mod tidy` and commit both `go.mod` and `go.sum`.

## Laptop slows mid-campaign
- Thermal throttling on the mobile CPU, not a resource fault. Plug in, ensure airflow, continue.
  Do NOT change host config to "fix" it.

---

## Linux process-creation telemetry: what actually blocks it

The README's "Linux Sysmon gap" is often read as *not configured yet*. It is more specific than
that, and both halves were verified on the 2026-08-29 lab host rather than assumed.

### auditd cannot run on a host whose kernel does not expose the audit subsystem

The victim image installs `auditd` and the compose override grants `AUDIT_CONTROL` /
`AUDIT_READ`. Those capabilities *are* effective inside the container — and it still fails:

```
$ docker exec purpleloop-victim auditctl -l
Error sending rule list data request (Operation not permitted)
```

This is not a container permissions problem. It fails identically with `--privileged` **and**
`--network host`, so it is neither a capability nor a network-namespace issue:

```
$ docker run --rm --privileged --network host --entrypoint sh purpleloop/victim:latest \
    -c "auditctl -s"
Error sending status request (Operation not permitted)
```

The host itself has no audit sysctls at all:

```
$ cat /proc/sys/kernel/audit_backlog_limit
cat: /proc/sys/kernel/audit_backlog_limit: No such file or directory
$ ls /proc/sys/kernel/ | grep -i audit     # no results
```

`kauditd` exists as a kernel thread, so `CONFIG_AUDIT` is compiled in, but the control
interface is unavailable. **On such a host, no amount of container configuration produces
auditd telemetry.**

### Sysmon for Linux requires systemd

Sysmon for Linux 1.5.2 installs and its eBPF objects are present (the host has
`/sys/kernel/btf/vmlinux`, so eBPF itself is fine). But it only runs as a systemd service:

```
$ /opt/sysmon/sysmon -i /opt/sysmon/config.xml -service
sh: 1: systemctl: not found
# process exits
```

The `-service` flag in the shipped unit's `ExecStart` still shells out to `systemctl`. The
victim container runs `tail -F` as PID 1, so there is no systemd for it to talk to.

### What this means for a run

The pipeline canary requires `category: process_creation`. With no process-creation source the
canary cannot fire, so every Linux run is correctly `INCONCLUSIVE` and coverage is suppressed.
**That is the canary working, not the canary failing.** Do not "fix" it by relaxing the canary
rule or by letting command-output telemetry satisfy a process-creation rule — the
evidence-fidelity gate exists precisely to refuse that, and removing it is how v1.0 produced a
false 100%.

### Closing it

Closing the gap needs a victim that can run systemd — a systemd-based image running privileged
with PID 1 as systemd, so Sysmon for Linux can install and start. That is a deliberate change
to the lab's security posture (a privileged container in a lab that otherwise runs
unprivileged), and it is a decision to take explicitly rather than drift into.

Until then, Windows Sysmon Event ID 1 is the platform where detection is demonstrated. The
`--settle-timeout` default of 60s is also below the victim's 360s `<localfile>` collection
interval; raise it if you want even low-fidelity command output to land inside a technique's
window.

## Why the Linux victim is not a container with Sysmon

Sysmon for Linux was built, run and measured on this lab before being rejected. Recording the
result so it is not re-attempted blind.

**It works.** With systemd as PID 1 (`privileged: true`, `cgroup: host`, `/sys/kernel/btf`
mounted) the service starts and emits genuine `EventID 1` process-creation events carrying
`Image`, `CommandLine`, `ParentImage` and `User` — exactly the fields the evaluator needs. The
undocumented `-service` flag in its own systemd unit is what runs it; it has no foreground mode.

**And it cannot be scoped to the victim.** Sysmon's eBPF is kernel-global. Inside a container it
observes every process on the host, and the event carries no container, cgroup or namespace
field — `RuleName`, `LogonId` and `TerminalSessionId` do not distinguish one. Measured results
from attempting to scope it after the fact by resolving the event's host PID through a
read-only `/proc` mount:

| Approach | Result |
|---|---|
| cgroup lookup on the event's PID | **Host binaries leaked.** `/usr/lib/cargo/bin/coreutils/tr`, `nvidia-smi`, `vmrun` — none of which exist in the Ubuntu image — were accepted. Short-lived host processes exit, the kernel recycles the PID, a container process takes it, and the lookup answers about the wrong process. |
| the same, plus verifying `/proc/<pid>/comm` matches the event's image | **No leakage, but most events lost.** Only processes living longer than the syslog→converter latency survive; `uname`, `id` and `who` — the atomics themselves — were dropped. |

Both directions are wrong in ways this project exists to prevent. The first manufactures false
`DETECTED` verdicts from activity typed on the host; the second manufactures false `MISSED` and
`NO_TELEMETRY` from a collector that simply could not keep up. There is no third signal in the
event to break the tie.

**The fix is a VM, not a container.** The Windows victim already is one, which is precisely why
Windows telemetry is unambiguous: everything the sensor sees belongs to the victim, because the
sensor and the victim share a kernel that nothing else uses. A Linux VM running Sysmon for Linux
would give the Linux side the same property.

The engine is already ready for it: the normalizer has a `data.sysmon` path with EventID-1
fidelity gating and tests (`internal/evaluator/sysmon_linux_test.go`), so a Linux-Sysmon source
needs no Go changes — only a Wazuh agent shipping the events with those keys. Note the events
are deliberately *not* mapped through `data.win.*`; that path is Wazuh's Windows eventchannel
convention and using it for Linux would make the telemetry misreport its own origin.
