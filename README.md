# Purple Loop

[![CI](https://github.com/jayelbotvibe-web/purple-loop/actions/workflows/ci.yml/badge.svg)](https://github.com/jayelbotvibe-web/purple-loop/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/jayelbotvibe-web/purple-loop)](https://github.com/jayelbotvibe-web/purple-loop/releases)
[![Go](https://img.shields.io/github/go-mod/go-version/jayelbotvibe-web/purple-loop)](https://go.dev)
[![License](https://img.shields.io/github/license/jayelbotvibe-web/purple-loop)](LICENSE)

> **Risk-driven detection validation.** Emulates the ATT&CK techniques that matter most —
> prioritized by real threat intel — and proves whether your Sigma detections catch them,
> with evidence.

---

## Why this exists

Red teams find gaps. Blue teams write detections. But few tools *prove* a Sigma rule actually fires
for the threats being exploited right now — the CISA KEV list, the CVEs making headlines. Purple
Loop closes that loop: given a prioritized list of threats (from the
[threat-intel-arbiter](https://github.com/jayelbotvibe-web/threat-intel-arbiter)), it emulates the
corresponding ATT&CK techniques in an isolated lab, collects real telemetry, evaluates the Sigma
rules, and produces an evidence-backed coverage report. No guessing, no presence-based fake numbers.

## How it works

```
threat-intel-arbiter ──→ priority-ordered plan ──→ Execute ──→ Collect ──→ Evaluate ──→ Report
                              ↑                        │           │          │            │
                         CVE → technique           Docker/SSH   Wazuh     Sigma rule    HTML
                         → atomic ID               Linux/Win    archives  native match  + JSON
```

1. **Feed** loads techniques from a plan, arbiter export, or emulation script
2. **Execute** runs Atomic Red Team tests on lab victims (Docker Linux + VMware Windows)
3. **Collect** queries Wazuh archives for raw telemetry in the execution window
4. **Evaluate** normalizes events and matches them against Sigma rules using a native Go parser
5. **Report** produces JSON, HTML coverage grid, or ATT&CK Navigator layer export

## Results  *(v1.2 — real Sigma matching, not presence-based)*

- **Windows:** canary `DETECTED` — Sysmon Event ID 1 flowing, pipeline healthy
- **Linux:** `NO_TELEMETRY` — Sysmon-for-Linux pending (auditd events lack process-creation fields)
- **Coverage:** honest, non-zero. Windows detection confirmed; Linux gap documented

```json
{
  "technique_id": "T1059.004",
  "verdict": "DETECTED",
  "rule_matched": "detections/windows/win_proc_create.yml",
  "events_collected": 73,
  "evidence": [{"id": "win-1", "rule": "win_proc_create", "matched": true}]
}
```

## Quickstart

```bash
# One-time setup
git clone https://github.com/jayelbotvibe-web/purple-loop.git && cd purple-loop
make host-prep && make lab-fetch && make lab-up && make verify

# Run the pipeline canary (proves telemetry → detect works)
make canary

# Run a campaign
go run ./cmd/purpleloop run --plan plans/discovery.yml

# Priority-ordered from threat-intel-arbiter
go run ./cmd/purpleloop run --arbiter testdata/arbiter-live.json --output report.html

# Multi-stage actor emulation
go run ./cmd/purpleloop run --emulation emulation/apt29-subset.yml
```

## The two-repo pipeline

Purple Loop pairs with **[threat-intel-arbiter](https://github.com/jayelbotvibe-web/threat-intel-arbiter)**:
the arbiter ingests MISP/KEV feeds, scores threats with SSVC, and exports a priority-ordered plan.
Purple Loop executes that plan and proves whether each threat is caught.

[`threat-intel-arbiter → arbiter-live.json → purple-loop run --arbiter`]

## Architecture

Full architecture in [DESIGN.md](DESIGN.md). The engine is built on five pluggable Go interfaces:
`Executor`, `Collector`, `Evaluator`, `Feed`, `Reporter` — swap any component without changing the
orchestrator. Lab runs isolated on `purpleloop-lab` Docker network.

## Detection-as-code

Every Sigma rule has **positive + negative fixtures**. CI enforces:
- All positives must match
- All negatives must reject
- A broken rule fails `go test ./internal/...` and turns CI red

```bash
go test ./internal/evaluator/ -v -run Regression
# Regression: 10 rules tested, all positive/negative fixtures correct
```

## Supported Sigma subset

The native Go matcher supports the Sigma specification subset needed for process-creation rules:
field modifiers (`contains`, `startswith`, `endswith`, `|all`), condition grammar (`and`/`or`/`not`/parens/`1 of them`/`all of them`), and case-insensitive matching. Not yet supported: regex, aggregation expressions, `near`, correlated rules.

## Limitations

- **Lab-contained only.** Never run against production or targets outside `purpleloop-lab`.
- **Linux Sysmon gap.** The Linux victim has command-output telemetry but not Sysmon process-creation events. This is a known gap; Windows Sysmon detection is confirmed working.
- **SSVC mapping.** The arbiter uses pre-SSVC labels (Schedule/Monitor/Track) mapped to SSVC v2.1 equivalents.

## License

MIT — see [LICENSE](LICENSE).
