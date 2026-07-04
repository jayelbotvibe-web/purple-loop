# End-to-End Test — 2026-07-04 16:36 UTC

## Architecture
```
threat-intel-arbiter (profile: threatlib)
    │  hermes -z "..." --profile threatlib
    ▼
testdata/arbiter-live.json (10 alerts, SSVC-scored)
    │
    ▼
purple-loop (Go engine)
    │  go run ./cmd/purpleloop run --arbiter ...
    ├── DockerExecutor (docker exec purpleloop-victim)
    ├── SSHExecutor  (ssh windows-vm@192.168.88.13)
    ├── WazuhCollector (grep archives.json)
    ├── PresenceEvaluator
    └── HTMLReporter → coverage report
    │
    ▼
Wazuh 4.9.2 SIEM
    ├── Agent 001: victim01 (Linux, Docker)
    └── Agent 002: windows-vm (Windows 11, VMware bridged)
```

## Pre-flight
| Check | Status |
|-------|--------|
| Wazuh manager | UP (6h+) |
| Wazuh indexer | UP, green |
| Wazuh dashboard | UP, port 5601 |
| Linux victim (agent 001) | UP, Active |
| Windows victim (agent 002) | UP, Active, 1508 events |
| SSH to Windows | Key-auth, firewall ON, port 22 only |
| Go build + vet | PASS |
| Tests (6 packages) | 9/9 PASS |

---

## Test 1: Build & Unit Tests
```
$ make build && make vet && go test ./internal/... -count=1
ok  collector  0.004s
ok  evaluator  0.002s
ok  executor   0.001s
ok  feed       0.003s
ok  mapping    0.002s
ok  model      0.002s
```
**Result: PASS** — all 6 packages compile, 9 tests green.

---

## Test 2: Cross-Profile Arbiter Dispatch
```
$ hermes -z "Export top 10 alerts..." --profile threatlib
Done. Exported 10 alerts to testdata/arbiter-live.json
- 3,162 bytes, valid JSON, {"alerts": [...]}
- All 10 Schedule action (highest priority)
- Each: id, action, severity, matched_apps, cves, techniques
```
**Result: PASS** — threat-intel-arbiter agent scored 1,147 alerts and exported top 10.

**Pitfall:** The dispatch command `hermes -z "prompt" --profile <name>` must have `--profile` AFTER the prompt. Putting it before silently applies to the current profile. The prompt should be specific about output format (JSON schema, file path). Large prompts (>300 chars) may time out at 120s — break into smaller steps.

---

## Test 3: Arbiter Campaign (Live Lab)
```
$ go run ./cmd/purpleloop run \
    --arbiter testdata/arbiter-live.json \
    --victim-container purpleloop-victim \
    --manager-container single-node-wazuh.manager-1 \
    --output /tmp/e2e-arbiter.html

Headline: Top 10 exploited-in-the-wild: 10 detected / 0 partial / 0 missed
DETECTED: 10, MISSED: 0
HTML: 2,546 bytes
```
**Result: PASS** — all 10 CVEs detected with real telemetry evidence.

**Pitfalls:**
1. **Archives vs Alerts:** The collector must use `archives.json` (all events), not `alerts.json` (rule-triggered only). Basic shell commands don't trigger Wazuh rules. Fixed in commit b170cd3.
2. **Time window:** 5-second windows miss events. Must use 10-minute windows with 10-second ingest delay. The Wazuh agent flushes periodically (~6 min for command outputs).
3. **Container names:** Docker Compose prefixes container names with the project directory. verify-lab.sh must resolve dynamically, not hardcode.

---

## Test 4: Windows Cross-Platform
```
$ ssh windows-vm@192.168.88.13 "hostname && whoami"
DESKTOP-MONE3R9
desktop-mone3r9\windows-vm

Total windows-vm events: 1,508
Latest: 2026-07-04T16:35:31Z | decoder: windows_eventchannel | EventChannel

Firewall: ON (all 3 profiles)
```
**Result: PASS** — SSH execution confirmed, Windows Event Channel telemetry flowing to Wazuh, firewall enabled (port 22 only).

**Pitfalls:**
1. **VMware Bridged over WiFi:** WiFi adapters often don't support promiscuous mode. Must set Virtual Network Editor → vmnet0 → explicitly select the WiFi adapter (not "Automatic"). Without this, bridged mode won't assign an IP.
2. **SSH key location:** Windows OpenSSH overrides `AuthorizedKeysFile` to `ProgramData\ssh\administrators_authorized_keys` for Administrators group members. Keys in `~/.ssh/authorized_keys` are ignored.
3. **ICMP blocked by default:** Windows Firewall blocks ping even when port 22 is allowed. Test with SSH, not ping.
4. **PowerShell in cmd.exe:** SSH sessions default to cmd.exe even on Windows. `Get-Date` and other PowerShell cmdlets fail unless prefixed with `powershell -Command`. Use `cmd /c` for simple commands.
5. **VM sleep:** VMware VMs may sleep after inactivity. Wazuh agent keeps sending keepalives, but SSH connections time out.

---

## Test 5: Multi-Stage Emulation
```
$ go run ./cmd/purpleloop run --emulation emulation/discovery-chain.yml --dry-run
Emulation: 8 techniques across stages
  T1033: DETECTED  T1087.001: DETECTED  T1082: DETECTED ...
```
**Result: PASS** — 3-stage plan (recon → system-info → network) with 8 techniques.

---

## Summary
| Test | Result | Time |
|------|--------|------|
| Build + Tests | 9/9 PASS | <1s |
| Arbiter dispatch | 10 alerts exported | ~30s |
| Arbiter campaign | 10/10 DETECTED | ~120s |
| Windows pipeline | SSH + 1508 events | ~15s |
| Emulation plan | 8 techniques, 3 stages | <1s |

**All tests pass. Cross-profile workflow confirmed. Cross-platform confirmed.**
