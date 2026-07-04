#!/usr/bin/env bash
set -euo pipefail
R="jayelbotvibe-web/purple-loop"   # <-- set to your repo

# labels
gh label create "phase-0" -c "#5A48C7" -f; gh label create "phase-1" -c "#7C5CFF" -f
gh label create "phase-2" -c "#8B7CFF" -f; gh label create "phase-3" -c "#45B9F0" -f
gh label create "phase-4" -c "#40D6A3" -f; gh label create "phase-5" -c "#F5B33F" -f
gh label create "infra" -c "#262E48" -f;  gh label create "feature" -c "#1A2138" -f
gh label create "docs" -c "#37416A" -f;   gh label create "blocked" -c "#FF5D73" -f
gh label create "needs-human" -c "#FF5D73" -f

# milestones (via API)
for m in "v0.1 Lab foundation" "v0.2 MVP loop" "v0.3 Engine & reports" \
         "v0.4 CI & Windows" "v0.5 Arbiter integration" "v1.0 Emulation & release"; do
  gh api repos/$R/milestones -f title="${m%% *}" -f description="$m" >/dev/null 2>&1 || true
done

iss(){ gh issue create -R "$R" -t "$1" -b "$2" -m "$3" ${4:+-l "$4"}; }

# --- Phase 0 (v0.1) ---
iss "Repo scaffolding & tooling" "Create dir structure per DESIGN.md §Repository, go.mod, .gitignore (incl .env, lab/secrets/), README skeleton, empty CI workflow. **AC:** \`go build ./...\` passes; tree matches DESIGN.md; pushed to phase-0 branch." "v0.1" "phase-0,infra"
iss "Host prep & resource check" "Set vm.max_map_count=262144 (persist in /etc/sysctl.d), verify docker+compose, confirm free RAM/disk. **AC:** \`sysctl vm.max_map_count\`=262144; \`docker compose version\` ok; ≥60GB free on NVMe." "v0.1" "phase-0,infra"
iss "Wazuh single-node compose" "lab/docker-compose.yml: manager+indexer+dashboard on network purpleloop-lab, indexer heap -Xms4g -Xmx4g, container limit ~8g. **AC:** dashboard loads; indexer cluster health green; API auth returns a token." "v0.1" "phase-0,infra"
iss "Ubuntu victim + telemetry pipeline" "Add Ubuntu victim container with Sysmon-for-Linux + auditd shipping to Wazuh. **AC:** trigger a shell event on victim, query Wazuh API, see the event within 30s. Document the query in README." "v0.1" "phase-0,infra"

# --- Phase 1 (v0.2) ---
iss "model package (types & proof chain)" "internal/model: Verdict, ProofChain, AtomicTest, Target, Event, RunResult, TimeWindow, TechniqueTask, CampaignResult. **AC:** compiles; ProofChain marshals to the JSON shape in DESIGN.md §Proof chain." "v0.2" "phase-1,feature"
iss "WazuhCollector (Collector iface)" "internal/collector: implement Query(window,host) against Wazuh API. **AC:** unit test with a recorded API fixture returns parsed []Event." "v0.2" "phase-1,feature"
iss "Executor: one Linux atomic + cleanup" "internal/executor: run one technique (e.g. T1059.004) via ssh/exec into the victim, capture RunResult, always Cleanup. **AC:** run leaves no residue (verify cleanup); RunResult has command+timestamps." "v0.2" "phase-1,feature"
iss "Evaluator: single Sigma rule match" "internal/evaluator: minimal Sigma match for one rule against []Event. **AC:** returns DETECTED on positive events, MISSED on empty." "v0.2" "phase-1,feature"
iss "Wire the loop in cmd/purpleloop" "cobra CLI: \`purpleloop run --technique T1059.004\` → select→execute→collect→evaluate→print proof chain JSON. **AC:** command prints a valid ProofChain with a verdict and evidence. Tag v0.2.0." "v0.2" "phase-1,feature"

# --- Phase 2 (v0.3) ---
iss "PriorityFeed iface + static YAML feed" "internal/feed: StaticFeed reads plan.yml → []TechniqueTask. **AC:** loads a 10-technique plan." "v0.3" "phase-2,feature"
iss "Orchestrator: run a campaign" "Loop over feed tasks, aggregate CampaignResult. **AC:** \`purpleloop run --plan discovery.yml\` runs all techniques and collects verdicts." "v0.3" "phase-2,feature"
iss "Reporter: JSON + HTML coverage" "internal/report: write campaign JSON and a self-contained HTML coverage report. **AC:** report opens in a browser and shows per-technique verdicts + counts." "v0.3" "phase-2,feature"
iss "ATT&CK Navigator layer export" "Emit a Navigator-compatible layer JSON coloured by verdict. **AC:** file imports cleanly into ATT&CK Navigator." "v0.3" "phase-2,feature"
iss "Seed 8-10 techniques, rules & mappings" "Add atomics, Sigma rules, and mappings/attack_rule_map.json entries for a Discovery-heavy plan. **AC:** discovery.yml runs end-to-end; ≥8 techniques. Tag v0.3.0." "v0.3" "phase-2,feature"

# --- Phase 3 (v0.4) ---
iss "Detection-as-code fixtures + sigma lint CI" "Add detections/tests/<rule>/{positive,negative}_events.jsonl; CI job lints/validates every rule. **AC:** CI fails on an intentionally broken rule, passes when fixed." "v0.4" "phase-3,infra"
iss "Regression test harness in CI" "CI runs each rule vs its fixtures; missing a positive or catching a negative fails the build. **AC:** green badge on main." "v0.4" "phase-3,infra"
iss "Windows victim VM + Sysmon" "lab/windows/: Vagrant/VMware provisioning for a Windows victim with Sysmon shipping to Wazuh. **AC:** Windows process events visible in Wazuh. Lab-only AV posture." "v0.4" "phase-3,infra"
iss "Windows Executor (WinRM) + atomics" "Add a WinRM executor and ≥3 Windows atomics with cleanup. **AC:** a Windows technique runs end-to-end to a verdict. Tag v0.4.0." "v0.4" "phase-3,feature"

# --- Phase 4 (v0.5) ---
iss "Arbiter feed adapter" "internal/feed: ArbiterFeed consumes threat-intel-arbiter output → priority-ordered []TechniqueTask. **AC:** given a sample arbiter export, tasks come out sorted by priority. RECONCILE the arbiter's actual score field name with DESIGN.md §Proof chain." "v0.5" "phase-4,feature"
iss "CVE→technique→atomic mapping" "mappings/: resolve a prioritised CVE to ATT&CK technique(s) to atomic test id(s). **AC:** a CVE from the arbiter maps to at least one runnable atomic." "v0.5" "phase-4,feature"
iss "Priority-ordered campaign + report narrative" "Run ordered by arbiter priority; report headline reads e.g. 'top-20 exploited-in-the-wild: 14 detected / 3 partial / 3 missed'. **AC:** report shows priority column and the headline. Tag v0.5.0." "v0.5" "phase-4,feature"

# --- Phase 5 (v1.0) ---
iss "Multi-stage emulation plan format + runner" "emulation/: define a chained plan schema and a runner that executes stages in order. **AC:** a 3-stage plan runs with per-stage verdicts." "v1.0" "phase-5,feature"
iss "One actor plan (e.g. APT29 subset)" "Add an intel-prioritised actor emulation plan. **AC:** plan runs end-to-end; per-actor coverage produced." "v1.0" "phase-5,feature"
iss "v1.0 polish & release" "README with diagram + sample report screenshot + full proof-chain sample; badges; CHANGELOG; final review. **AC:** a newcomer can understand and run it from the README. Tag v1.0.0 + release." "v1.0" "phase-5,docs"

echo "Backlog created."
