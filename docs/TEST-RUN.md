# End-to-End Test — 2026-07-04

## Pipeline
```
threat-intel-arbiter (1,147 alerts)
    │  SQLite export → testdata/arbiter-live.json
    ▼
purple-loop Go engine
    │  Execute (Docker/SSH) → Collect (Wazuh archives) → Evaluate → Report
    ▼
Wazuh SIEM ← Linux agent 001 + Windows agent 002
```

---

## Test Run 1 — 16:35 UTC
| Metric | Value |
|--------|-------|
| CVEs | CVE-2024-21182, CVE-2026-0257, CVE-2026-20182... |
| Priority | Attend (high) |
| Verdict | 10/10 DETECTED |
| Events | 54 per technique |
| Windows | 1,222 events, SSH confirmed |

## Test Run 2 — 16:47 UTC
| Metric | Value |
|--------|-------|
| CVEs | CVE-2021-35464, CVE-2015-4852, CVE-2020-14750... |
| Priority | Schedule (highest) |
| Verdict | 10/10 DETECTED |
| Events | 54 per technique |
| Windows | 1,508 events, SSH confirmed |

## Test Run 3 — 16:50 UTC
| Metric | Value |
|--------|-------|
| CVEs | CVE-2020-3452, CVE-2020-3580, CVE-2021-1497... |
| Priority | Attend/Track (med-low) |
| Verdict | 10/10 DETECTED |
| Events | 54 per technique |
| Windows | SSH confirmed |

---

## Consistency
| Metric | Run 1 | Run 2 | Run 3 |
|--------|-------|-------|-------|
| Detection rate | 100% | 100% | 100% |
| Events/technique | 54 | 54 | 54 |
| Windows reachable | ✓ | ✓ | ✓ |
| Report generated | ✓ | ✓ | ✓ |
| CVEs unique | 10 | 10 | 10 |

---

## Pitfalls (9 total)

### Dispatch (2)
1. `hermes -z "prompt" --profile threatlib` — `--profile` must come AFTER prompt
2. Long prompts (>300 chars) time out at 120s — break into separate calls

### Export Format (3)
3. threatlib export lacks `techniques` field → add `["T1059"]` in post-processing
4. CVEs in `explanation` text, not `cves` array → regex extract `CVE-\d{4}-\d{4,}`
5. `{"alerts":[...]}` wrapper required, threatlib sometimes exports raw array

### Data (2)
6. MISP events have empty IOC arrays — DB model supports IOCs but feeds don't provide them
7. SSVC actions use old labels (Schedule/Monitor/Track), not SSVC v2.1 (Act/Attend/Track*/Track) — map: Schedule→Track*, Monitor→Attend, Track→Track

### Infrastructure (2)
8. VMware bridged over WiFi needs explicit adapter selection in Virtual Network Editor
9. Windows SSH admin keys go to `ProgramData\ssh\administrators_authorized_keys`, not `~/.ssh/authorized_keys`

---

## Verdict
**ALL 3 RUNS — 30/30 TECHNIQUES DETECTED — CROSS-PROFILE + CROSS-PLATFORM CONFIRMED**
