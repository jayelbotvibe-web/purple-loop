# Purple Loop

Risk-driven detection validation. A Go purple-team engine that proves whether you
can detect the threats that matter — in priority order, with evidence. It closes
the loop between **threat-intel-arbiter** (what matters) and **your detections**
(can you catch it).

> **Status:** Phase 0 complete — Wazuh stack + victim running, telemetry pipeline verified.

## What works today
- CLI skeleton runs the full core loop in dry mode and prints a proof chain:
  ```bash
  go run ./cmd/purpleloop run --technique T1059.004 --dry-run
  ```
- Pluggable interfaces (`internal/model`) for feed, executor, collector,
  evaluator, reporter — each with a stub implementation.
- Lab telemetry pipeline: Wazuh 4.9.2 single-node + Ubuntu 22.04 victim,
  agent enrolled, events flowing. Query via API:
  ```bash
  # Get agent status
  curl -k -u wazuh-wui:<pass> -X POST "https://<manager>:55000/security/user/authenticate?raw=true"
  curl -k -H "Authorization: Bearer <token>" "https://<manager>:55000/agents?agents_list=001"
  ```

## Quickstart (once the lab lands — Phase 0)
```bash
cp .env.example .env         # fill in lab secrets (gitignored)
make host-prep               # one-time host tweak (vm.max_map_count)
make lab-fetch               # pull pinned Wazuh single-node + Atomic Red Team
make lab-up                  # bring the stack + victim up
make verify                  # binary health check — must pass before proceeding
make run TECHNIQUE=T1059.004 # validate one technique end-to-end
```

## Layout
See `DESIGN.md` (Repository layout). Planning docs — `DESIGN.md`,
`AGENT_PLAYBOOK.md` — are the source of truth; the agent reads them before acting.

## The two-repo pipeline
`threat-intel-arbiter` decides **what** to test (exploited-in-the-wild CVEs →
ATT&CK techniques). Purple Loop proves **whether it's caught**, in priority order.
