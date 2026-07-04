# Purple Loop

[![CI](https://github.com/jayelbotvibe-web/purple-loop/actions/workflows/ci.yml/badge.svg)](https://github.com/jayelbotvibe-web/purple-loop/actions/workflows/ci.yml)
[![Go 1.22+](https://img.shields.io/badge/Go-1.22+-00ADD8?logo=go)](https://go.dev)
[![License MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Risk-driven detection validation. A Go purple-team engine that proves whether you
can detect the threats that matter — in priority order, with evidence.

> **Status:** v1.0 — 24/24 issues closed. Linux + Windows victims, live telemetry,
> campaigns producing real DETECTED verdicts with evidence.

## What it does

```
Priority feed → Select → Execute → Collect → Evaluate → Prove → Report
```

1. **Priority feed** — CVEs + ATT&CK techniques from threat-intel-arbiter, sorted by SSVC action
2. **Execute** — run Atomic Red Team tests on lab victims (Linux via Docker, Windows via VMware)
3. **Collect** — query Wazuh SIEM for telemetry in the execution window
4. **Evaluate** — match Sigma detection rules against collected events
5. **Prove** — produce a verdict (DETECTED/PARTIAL/MISSED) with the raw evidence chain
6. **Report** — JSON, HTML coverage grid, ATT&CK Navigator layer

## Quickstart

```bash
cp .env.example .env
make host-prep               # vm.max_map_count + tooling check
make lab-fetch               # pull Wazuh 4.9.2 + Atomic Red Team
make lab-up                  # start manager, indexer, dashboard, victim
make verify                  # health check

# Single technique
go run ./cmd/purpleloop run --technique T1059.004 \
  --victim-container purpleloop-victim \
  --manager-container single-node-wazuh.manager-1

# 10-technique campaign
go run ./cmd/purpleloop run --plan plans/discovery.yml --output report.html

# Priority-ordered from arbiter
go run ./cmd/purpleloop run --arbiter testdata/arbiter-export.json --output report.html
```

### Windows victim (optional)

```bash
# On the Windows VM (PowerShell as Admin):
# 1. Copy lab/windows/provision.ps1 to the VM
# 2. Run: powershell -ExecutionPolicy Bypass -File provision.ps1
# 3. Set up SSH: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
#    Start-Service sshd; Set-Service -Name sshd -StartupType Automatic
# 4. Copy your SSH key: ssh-copy-id windows-vm@<windows-ip>
```
# Multi-stage actor emulation
go run ./cmd/purpleloop run --emulation emulation/apt29-subset.yml --output report.html

# Dry-run (no lab needed)
go run ./cmd/purpleloop run --plan plans/discovery.yml --dry-run
```

## Sample output

```
$ go run ./cmd/purpleloop run --plan plans/discovery.yml --dry-run
{
  "started_at": "2026-07-04T11:06:26Z",
  "chains": [
    {
      "technique_id": "T1059.004",
      "atomic": {"id": "T1059.004-1", "command": "id; whoami", "executor": "sh"},
      "executed_at": "2026-07-04T11:06:26Z",
      "events_collected": 1,
      "rule_matched": "detections/linux/proc_creation_susp_shell.yml",
      "verdict": "DETECTED",
      "evidence": [{"event_id": "dry-0001", ...}]
    }
  ]
}
```

HTML report shows priority column, CVE, verdict breakdown, and narrative headline:
*"Top 10 exploited-in-the-wild: 10 detected / 0 partial / 0 missed"*

## The two-repo pipeline

| Repo | Role |
|------|------|
| [threat-intel-arbiter](https://github.com/jayelbotvibe-web/threat-intel-arbiter) | Decides **what** to test (exploited CVEs → ATT&CK) |
| **purple-loop** (this repo) | Proves **whether it's caught**, in priority order |

## Layout

```
purple-loop/
├── cmd/purpleloop/          CLI entrypoint (stdlib flag)
├── internal/
│   ├── feed/                StaticFeed, ArbiterFeed, EmulationPlan
│   ├── executor/            DockerExecutor, DryExecutor
│   ├── collector/           WazuhCollector (alerts.json)
│   ├── evaluator/           PresenceEvaluator
│   ├── report/              JSON, HTML, Navigator layer
│   ├── model/               Types + interfaces
│   └── mapping/             CVE → technique → atomic resolver
├── detections/              10 Sigma rules + fixtures
├── emulation/               Multi-stage actor plans
├── plans/                   Campaign plan YAML
├── scripts/                 lint-sigma, regression-test, verify-lab
├── lab/                     Docker Compose override + victim
└── testdata/                Arbiter export fixtures
```

## Detection-as-code

Every Sigma rule has positive/negative fixtures. CI validates:

- Rule schema (required fields present)
- Fixture files exist and are valid JSONL
- `go build ./cmd/... ./internal/...` + `go test ./internal/...` + `go vet`

## Phases

| Version | Phase | Status |
|---------|-------|--------|
| v0.1.0 | Lab foundation | ✓ |
| v0.2.0 | MVP loop | ✓ |
| v0.3.0 | Engine & reports | ✓ |
| v0.4.0 | CI & Windows | ✓ Linux + Windows victims, Sysmon, SSH executor |
| v0.5.0 | Arbiter integration | ✓ |
| v1.0.0 | Emulation & release | ✓ |
