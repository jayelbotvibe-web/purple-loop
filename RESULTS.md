# Results

## Live run — 2026-08-29, Linux victim

```
$ purpleloop run --technique T1082 \
    --victim-container purpleloop-victim \
    --manager-container single-node-wazuh.manager-1

INCONCLUSIVE: canary not detected on linux — coverage will not be reported as valid
```

| | |
|---|---|
| Atomic resolved | `T1082-3` — *List OS Information* (`uname -a`, `/etc/os-release`, …) |
| Source | Atomic Red Team @ `9415359` |
| Canary | **not detected** on linux |
| Run verdict | `INCONCLUSIVE` — coverage suppressed |
| Technique verdict | `INCONCLUSIVE` |
| Events collected | 0 (`no telemetry arrived within 1m3s of execution`) |

**This is the correct outcome, and it is the point of the canary.** The Linux victim ships
command-output telemetry (`<localfile>` command monitoring on a 360-second cycle) but no
process-creation source. The canary rule requires `category: process_creation`, so the positive
control cannot fire, so the pipeline is unproven — and an unproven pipeline may not report
coverage. Every technique in the run is `INCONCLUSIVE` rather than `MISSED`, because a missed
detection is a claim about a rule and nothing here tested a rule.

The three trust contracts were verified against this run:

- the per-run artifact was written to `reports/runs/<id>/coverage.json` for inspection;
- it was **not** appended to `reports/history.json`;
- it was **not** published to `docs/data/coverage.json`.

**To close this gap** the Linux victim needs Sysmon-for-Linux (or auditd `execve` forwarding
that carries `Image`/`CommandLine`). Windows Sysmon Event ID 1 is confirmed working and is the
platform where detection has been demonstrated.

---

## What the previous version of this file claimed

The file previously held a single JSON blob reporting:

```json
{"technique_id":"T1059.004","verdict":"DETECTED",
 "rule_matched":"detections/windows/win_proc_create.yml",
 "evidence":[{"fields":{"Image":"C:\\Windows\\SysWOW64\\net.exe",
   "ParentImage":"C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"}}]}
```

Three things are wrong with it, all consequences of the engine defect fixed in the 2026-08
changelog entries:

1. **`T1059.004` is Bash on Linux.** The evidence is a Windows process.
2. **The rule credited is the Windows rule**, not the Linux rule for that technique.
3. **The "attack" is the monitoring agent itself** — `net.exe` spawned by `wazuh-agent.exe`.
   Nothing the atomic did produced this event.

The old engine executed `id; whoami` for every technique, collected whatever appeared in a
ten-minute window, and credited an unrelated match. The evidence-fidelity gate, the corrected
window, the platform check and the atomic resolver each independently prevent this result now.
It is kept here because a project that claims evidence should show what its own bad evidence
looked like.
