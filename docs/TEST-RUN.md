# End-to-End Test — 2026-07-04

## v1.1.0 — Real Detection Evaluation

### Pipeline
```
threat-intel-arbiter → arbiter-live.json → purple-loop (Sigma matcher) → Wazuh SIEM
```

### Verdict Semantics (v1.1)
| Verdict | Meaning |
|---------|---------|
| DETECTED | Event matched a Sigma rule's condition |
| MISSED | Events collected, no rule matched — real gap |
| NO_TELEMETRY | Zero events in collection window |
| ERROR | Rule parse/evaluator failure |

---

## Test Results (v1.1)

### Dry-Run (validates pipeline)
```
$ go run ./cmd/purpleloop run --technique T1059.004 --dry-run
T1059.004: DETECTED | rule_matched=proc_creation_susp_shell.yml | evidence=1
```
**PASS** — synthetic event matches the sample rule.

### Unmapped Technique (discriminator)
```
$ go run ./cmd/purpleloop run --technique T9999 --dry-run
T9999: MISSED — no rule exists, no match possible
```
**PASS** — proves evaluator is rule-based, not presence-based.

### Live Campaign
```
$ go run ./cmd/purpleloop run --plan plans/discovery.yml
10 techniques: 0 DETECTED, 10 MISSED
```
**PASS (honest)** — telemetry exists but lacks process-creation fields.

### Known Gap
Lab telemetry sources (command output, SCA, Event Channel) lack Sysmon process creation (Event ID 1) fields (Image, ParentImage, CommandLine). Sigma rules require these fields. Without Sysmon Event ID 1 telemetry, real detection evaluation produces MISSED for all process-creation rules.

---

## Regression Test
```
$ go test ./internal/evaluator/ -v -run Regression
10 rules, 20 fixtures: all positive match + negative reject
```
**PASS**

## Pitfalls (v1.0 → v1.1)
| # | Category | Pitfall |
|---|----------|---------|
| 1 | Presence | v1.0 "100%" was any-events=detected, not rule-based |
| 2 | Telemetry | No Sysmon Event ID 1 — rules need process-creation fields |
| 3 | Dry-run | Must emit canonical fields (Image, ParentImage) for matcher |
| 4 | CI scope | `go test ./...` fails on vendored lab dirs — use `./internal/...` |
