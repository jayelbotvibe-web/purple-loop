# Purple Loop — Architecture Plan

**Repo:** `github.com/jayelbotvibe-web/purple-loop`

---

## 1. Overview

Purple Loop is a Go purple-team engine that validates detection coverage in risk-priority order. It closes the loop between **threat-intel-arbiter** (which CVEs/techniques matter right now) and **your SIEM** (can you actually detect them).

**What makes it different:**
- **Risk-driven order** — Validation sequenced by threat-intel-arbiter output. You test the exploited-in-the-wild threats first.
- **Proof chains** — Every verdict ships with the raw log evidence that justifies it. No "trust me" — the matching event is attached.
- **Detection-as-code** — Sigma rules are versioned, linted, and regression-tested in CI. A rule that stops firing fails the build.
- **Real engineering** — Go interfaces, fixtures, CI, semantic-versioned releases. Same tier as the existing arbiter, not a tutorial follow-along.

## 2. The Core Loop

```
Priority feed → Select → Execute → Collect → Evaluate → Prove → Report
```

1. **Priority feed** — prioritised CVEs + ATT&CK techniques from threat-intel-arbiter
2. **Select** — map each technique → concrete Atomic test IDs via the mapping dataset
3. **Execute** (offense) — run the atomic on the target host. Record command, host, timestamp
4. **Collect** (defense) — query the SIEM for events in the exact run window on that host
5. **Evaluate** (defense) — run the Sigma rule(s) against the collected events
6. **Prove** (verdict) — DETECTED / MISSED + the evidence that supports it
7. **Report** — coverage matrix, ATT&CK Navigator layer, JSON + HTML

Red = offense (execute). Blue = defense (collect + evaluate). Purple = verdict (prove + report).

## 3. System Architecture — Three Planes

### Intel Plane
- **threat-intel-arbiter** — prioritised CVEs → ATT&CK techniques
- Delivers ordered `[]TechniqueTask` to the engine via the `PriorityFeed` interface

### Engine Plane (Go, this repo)
The brain. Built around swappable Go interfaces:

| Interface | Role | First impl | Swap later |
|-----------|------|------------|------------|
| `PriorityFeed` | Consumes prioritised work | Static YAML feed | arbiter adapter (Phase 4) |
| `Executor` | Runs atomics on targets | SSH-to-container | WinRM (Phase 3) |
| `Collector` | Queries SIEM telemetry | WazuhCollector | Elastic/Splunk |
| `Evaluator` | Matches Sigma rules | Presence evaluator | Full Sigma engine |
| `Reporter` | Verdicts, proof chains, reports | JSON stdout | HTML + Navigator |

### Lab Plane (Docker)
- Wazuh SIEM (manager + indexer + dashboard, pinned official single-node deployment)
- Ubuntu victim container(s) with Wazuh agent + auditd
- Windows victim VM (Phase 3) with Sysmon
- Telemetry shippers: Sysmon (Windows), auditd (Linux)
- All on isolated Docker network `purpleloop-lab`

```
Intel plane ──→ Engine plane ←── Lab plane
 (arbiter)       (Go interfaces)   (Wazuh + victims)
```

## 4. The Proof Chain

For every technique tested, the engine emits the full evidence trail:

```json
{
  "technique_id": "T1059.004",
  "source_cve": "CVE-2025-XXXXX",
  "arbiter_priority": 0.91,
  "atomic": {
    "id": "T1059.004-1",
    "command": "sh -c '…'",
    "executor": "bash"
  },
  "executed_at": "2026-07-04T09:12:03Z",
  "events_collected": 3,
  "rule_matched": "proc_creation_susp_shell.yml",
  "verdict": "DETECTED",
  "evidence": [{ "event_id": "…", "raw": "…" }]
}
```

Fields explained:
- **source_cve + arbiter_priority** — Why this test ran now, traceable to a real exploited vulnerability
- **atomic.command** — Exactly what was executed on the victim, reproducibly
- **events_collected** — Telemetry the attack actually generated
- **rule_matched** — The specific Sigma rule that fired (blank if none did)
- **evidence[]** — The raw log line itself. The "show me" that most portfolios can't produce.

## 5. Tech Stack (chosen for $0 budget, your hardware)

| Layer | Choice | Why |
|-------|--------|-----|
| Engine | **Go** | Continuity with threat-intel-arbiter; single static binary; strong CLI + test story |
| Lab orchestration | **Docker Compose** | Linux victims as cheap containers. One Windows VM added later |
| SIEM | **Wazuh** | Free, single-node manager + indexer + dashboard with REST API |
| Telemetry | **Sysmon + auditd** | Rich process/network events; Wazuh decodes out of the box |
| Attack execution | **Atomic Red Team** | Battle-tested atomics, built-in cleanup, ATT&CK-mapped |
| Detections | **Sigma** | Vendor-neutral, industry standard, CI-friendly as code |
| Seed mapping | **AttackRuleMap** | Bootstraps atomic→Sigma/Splunk links |
| CI | **GitHub Actions** | Lints + regression-tests detections on every PR |

## 6. Detection-as-Code

Each Sigma rule ships with:
- **positive fixtures** (events it MUST catch)
- **negative fixtures** (events it must NOT catch — false-positive guard)

CI runs them on every change:
```
Open PR → Lint → Regression test (positive/negative fixtures) → Build passes/fails
```

```
detections/
  linux/
    proc_creation_susp_shell.yml
  tests/
    proc_creation_susp_shell/
      positive_events.jsonl   # MUST match
      negative_events.jsonl   # must NOT match — FP guard
```

## 7. Repository Layout

```
purple-loop/
├── cmd/purpleloop/            # CLI entrypoint (cobra)
├── internal/
│   ├── feed/                  # PriorityFeed: arbiter adapter
│   ├── executor/              # ssh, agent, invoke-atomic wrappers
│   ├── collector/             # wazuh, elastic (pluggable)
│   ├── evaluator/             # sigma matching
│   ├── report/                # json, html, navigator-layer
│   └── model/                 # Verdict, ProofChain, Campaign…
├── detections/                # Sigma rules + regression fixtures
├── mappings/                  # attack_rule_map.json + CVE→technique
├── lab/                       # docker-compose.override.yml, victim Dockerfile
├── emulation/                 # multi-stage actor plans (Phase 5)
├── .github/workflows/ci.yml   # lint + regression + smoke
├── README.md
└── DESIGN.md
```

## 8. Phased Roadmap

Each phase is a complete, portfolio-worthy state on its own.

### Phase 0 · Lab foundation (v0.1)
Stand up the telemetry pipeline. Docker Compose: Wazuh single-node + Ubuntu victim. Sysmon + auditd ship events; confirm you can query them over the API.
**Deliverable:** A working telemetry pipeline, documented.

### Phase 1 · MVP loop (v0.2)
One technique, end to end. Hardcode one technique. Run its atomic, query Wazuh, match one Sigma rule, print a proof chain.
**Deliverable:** A DETECTED/MISSED verdict with evidence for a single technique.

### Phase 2 · Engine & reports (v0.3)
Drive a multi-technique campaign from a YAML plan. Emit JSON + HTML coverage and ATT&CK Navigator layer.
**Deliverable:** `purpleloop run --plan discovery.yml` → a report you can screenshot.

### Phase 3 · CI & Windows (v0.4)
Detection-as-code CI green. Cross-platform: Windows victim VM + Sysmon + Windows executor.
**Deliverable:** Green CI badge and cross-platform coverage.

### Phase 4 · Arbiter integration (v0.5) — *the headline*
Feed adapter consumes threat-intel-arbiter output. Campaigns run in priority order. Report headline: "top-20 exploited-in-the-wild: 14 detected, 3 missed."
**Deliverable:** The risk-driven story, fully wired. Interview centrepiece.

### Phase 5 · Emulation & release (v1.0)
Multi-stage actor emulation plans. Polished v1.0 with full README, diagram, sample report, badges, CHANGELOG.
**Deliverable:** A newcomer can understand and run the project from the README.

## 9. Hardware Footprint

**Machine:** i7-11800H (8c/16t), 32 GB, NVMe SSD, dedicated to the lab.

| Component | Allocation | Note |
|-----------|-----------|------|
| Wazuh indexer JVM heap | `-Xms4g -Xmx4g` | Cap it — auto-sizing grabs too much |
| Wazuh indexer container | 6–8 GB limit | Heap plus overhead |
| Windows victim VM (Phase 3) | 4 vCPU · 6–8 GB | Leaves 4 cores, ~24 GB for host |
| Linux victim container(s) | 0.5–1 GB each | Defaults fine |
| Host tweak (required) | `vm.max_map_count=262144` | Indexer won't start without it |
| Host tweak (retention) | 7-day ILM | Keeps indexer from growing unbounded |

**Peak RAM:** ~15-17 GB (Linux phases 0-2), ~21-24 GB (full system with Windows).
**One laptop caveat:** sustained all-core load may throttle turbo on this mobile chip — expected, not a resource fault. Run plugged in.

## 10. Integration with threat-intel-arbiter

> "The arbiter tells me which CVEs are exploited in the wild and maps them to ATT&CK techniques. Purple Loop then emulates exactly those techniques and proves whether my detections catch them — so my detection engineering effort goes to the threats actually being weaponised, in priority order, with evidence."

- **Arbiter** — Decides what matters. CVE prioritisation from MISP + CISA KEV, mapped to ATT&CK techniques.
- **Purple Loop** — Proves you can catch it. Emulates the technique, validates the behavioral detection, attaches evidence. Does not validate IOCs — the arbiter passes techniques, not indicators.
- **Together** — Risk-driven behavioral detection assurance. A full pipeline no single portfolio repo shows.
