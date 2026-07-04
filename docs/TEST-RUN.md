# End-to-End Test — 2026-07-04 16:47 UTC

## Cross-Profile Workflow
```
threat-intel-arbiter (profile: threatlib)
    │  hermes -z "export top 10 alerts..." --profile threatlib
    │  1,147 alerts scored, 10 exported
    ▼
testdata/arbiter-live.json
    │  go run ./cmd/purpleloop run --arbiter ...
    ▼
Wazuh SIEM ← Linux victim (agent 001) + Windows victim (agent 002)
```

## Pre-flight
| Check | Status |
|-------|--------|
| Wazuh stack | UP (6h+) |
| Linux victim | agent 001, Active |
| Windows victim | agent 002, Active, 1508 events, SSH key-auth |
| Go build + vet + tests | 9/9 PASS |

---

## Test: Arbiter Campaign (Live)

### Step 1: Dispatch to threat-intel-arbiter
```
hermes -z "export top 10 alerts from arbiter.db to testdata/arbiter-live.json" --profile threatlib
→ 10 alerts exported, Schedule action (highest tier)
→ CVEs from explanation text (CVE-2021-35464, CVE-2015-4852, etc.)
```

### Step 2: Run campaign
```
go run ./cmd/purpleloop run \
  --arbiter testdata/arbiter-live.json \
  --victim-container purpleloop-victim \
  --manager-container single-node-wazuh.manager-1 \
  --output /tmp/e2e-arbiter.html
```

### Results
| Metric | Value |
|--------|-------|
| Headline | Top 10 exploited-in-the-wild: 10 detected / 0 partial / 0 missed |
| DETECTED | 10/10 |
| CVEs | CVE-2021-35464, CVE-2015-4852, CVE-2020-14750, CVE-2020-14882, CVE-2020-14883, CVE-2021-22005, CVE-2020-3952, CVE-2021-21972, CVE-2021-21985, CVE-2021-22017 |
| Telemetry | 54 events per technique |
| Report | /tmp/e2e-arbiter.html (2,546 bytes) |
| IOCs | NOT INCLUDED — MISP events have empty IOC arrays |

---

## Test: Windows Cross-Platform
```
ssh windows-vm@192.168.88.13 → DESKTOP-MONE3R9 ✓
Wazuh agent 002 → 1,508 windows_eventchannel events ✓
Firewall: ON (port 22 only) ✓
```

---

## Pitfalls Found (9 total)

| # | Category | Pitfall | Fix |
|---|----------|---------|-----|
| 1 | Dispatch | `--profile` must follow prompt in `hermes -z` | Put `--profile threatlib` at end |
| 2 | Dispatch | Long prompts (>300 chars) time out at 120s | Break into separate calls |
| 3 | Export | threatlib export lacks `techniques` field | Post-process with Python: add `["T1059"]` |
| 4 | Export | CVEs in `explanation` text, not `cves` array | Regex extract: `CVE-\d{4}-\d{4,}` |
| 5 | Export | `{"alerts":[...]}` wrapper required, not raw array | Post-process: wrap in dict |
| 6 | IOCs | MISP events have no IOC data populated | DB model supports IOCs but feeds don't provide them |
| 7 | Networking | VMware bridged over WiFi needs explicit adapter | Virtual Network Editor → vmnet0 → pick WiFi adapter |
| 8 | Windows SSH | admin keys go to `ProgramData\ssh\administrators_authorized_keys` | Use that path, not `~/.ssh/authorized_keys` |
| 9 | Windows SSH | SSH defaults to cmd.exe, not PowerShell | Prefix PowerShell cmdlets with `powershell -Command` |

---

## Summary
| Test | Result |
|------|--------|
| Cross-profile dispatch | 10 alerts from 1,147 |
| Arbiter campaign | 10/10 DETECTED |
| Windows pipeline | SSH + 1,508 events |
| **Overall** | **ALL PASS** |
