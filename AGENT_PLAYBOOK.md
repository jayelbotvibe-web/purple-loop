# Purple Loop — Agent Execution Playbook

**Audience:** the Hermes desktop build agent (primary) and the human maintainer (setup).
**Companion doc:** `DESIGN.md` (architecture — read it first).
**Repo:** `github.com/jayelbotvibe-web/purple-loop`  *(rename freely; used throughout as `$REPO`)*

This playbook is the single source of truth for *how the work gets executed*. `DESIGN.md`
says **what** we're building; this says **how the agent builds it, verifies it, and records it in
git** — one issue at a time, without going off the rails.

---

## 0. How the human hands this off (do this once)

1. Create the repo and push the two planning docs before involving the agent:
   ```bash
   gh repo create jayelbotvibe-web/purple-loop --private --clone
   cd purple-loop
   cp /path/to/DESIGN.md /path/to/AGENT_PLAYBOOK.md .
   git add . && git commit -m "docs: add architecture and agent playbook" && git push
   ```
2. Make sure the agent's machine has: `git`, `gh` (authenticated via `gh auth login`), `go` (1.22+),
   `docker` + `docker compose`, and network access. Secrets (GitHub token, any lab passwords) are
   provided through `gh auth` and a **gitignored** `.env` — never pasted into files that get committed.
3. Give the agent the **Kickoff Prompt** in Section 8. That's the only inline text it needs — it reads
   everything else from the repo.

---

## 1. Agent role & mission

You are the build agent for **Purple Loop**, a Go purple-team engine that validates detection
coverage in risk-priority order (full rationale in `DESIGN.md`). Your mission is to execute the
phased plan (Phase 0 → Phase 5) as a sequence of GitHub Issues, producing working, tested,
committed software at each step, so that at any moment the repo is in a demonstrable state.

You optimise for **correctness and traceability over speed**. A smaller, verified, committed
increment always beats a large unverified one.

---

## 2. Operating contract (non-negotiable rules)

**Work unit**
- Work **one issue at a time**, taking the lowest-numbered open issue in the **current milestone**.
- Never start a new phase's milestone until the previous phase is closed (PR merged, tag pushed).

**Before you start an issue**
- Read the issue and its acceptance criteria. Restate, in an issue comment, your plan in 2–4 bullets.
- If anything is ambiguous or under-specified → **STOP and ask** (see stop conditions).

**While working**
- Make **small, frequent commits** using Conventional Commits (Section 4). Each commit references the
  issue (`#N`).
- After every step that has a **verification command**, run it and paste the result into the issue
  comment. Do not proceed past a failed verification.

**Finishing an issue**
- All acceptance criteria met and verified → commit, update `PROGRESS.md`, then close the issue with
  `git commit ... "closes #N"` or `gh issue close`.
- Never close an issue on unverified or partial work. If blocked, label it `blocked` and stop.

**Bounded debugging**
- If a verification fails, debug it — but cap at **3 serious attempts**. If still failing, stop, label
  the issue `blocked`, write what you tried and the exact error, and report to the human. Do not thrash
  or start rewriting unrelated code.

**Stop-and-ask conditions (halt and report immediately)**
- Anything destructive to the host outside the project dir (deleting volumes/VMs, changing host
  security config beyond the one documented `vm.max_map_count` tweak).
- Anything needing a credential, paid service, or account you don't have.
- A verification that fails after 3 attempts, or an error you don't understand.
- Any deviation from `DESIGN.md` you think is warranted — propose it, don't just do it.
- Scope you can't map to an existing issue — propose a new issue instead of silently expanding one.

**Secrets**
- Never commit secrets. Wazuh/API passwords, tokens, and generated cert material go in a gitignored
  `.env` or `lab/secrets/` (also gitignored). If you generate credentials, record only their *location*
  in `PROGRESS.md`, never their values.

---

## 3. Lab containment & safety (this project runs attack tooling)

Purple Loop executes Atomic Red Team tests. These are benign, reversible test behaviours, but treat
the lab as a live-fire range and keep it fully contained:

- All victims and the SIEM run on a **dedicated, isolated Docker network** (`purpleloop-lab`). Attacks
  **only ever target hosts inside that network** — never the host, never anything on the internet, never
  the user's other VMs.
- **Always run the atomic's Cleanup** after execution. Verify cleanup succeeded before the next test.
- Prefer **snapshots**: before a campaign, snapshot victim containers/VMs; restore after, so state can't
  drift.
- The Windows victim (Phase 3) has Defender/AV posture set **only** inside the lab VM, never on the host.
- If any test would require disabling host protections or reaching outside the lab network → STOP.

---

## 4. Git & GitHub workflow (the repo is updated continuously)

**Branching**
- `main` is always green and demonstrable.
- One branch per phase: `phase-0/lab-foundation`, `phase-1/mvp-loop`, etc. Do all of a phase's issues
  on its branch.
- Open a **PR** when the phase's issues are done; merge to `main` only when CI is green.

**Commits — Conventional Commits**
```
feat(collector): implement Wazuh Query over REST API (#6)
fix(executor): run atomic cleanup on non-zero exit (#7)
docs: record Phase 0 verification results (#4)
chore(ci): add sigma lint workflow (#15)
test(evaluator): add positive/negative fixtures (#16)
```
Types: `feat, fix, docs, test, chore, refactor, ci`. Always append `(#issue)`.

**Living documents — update as you go**
- `PROGRESS.md` — append a dated line per issue closed: what shipped, verification result, commit hash.
- `README.md` — keep the "Status", "Quickstart", and "What works today" sections current each phase.
- `CHANGELOG.md` — Keep-a-Changelog format; a bullet per user-visible change.

**Milestones & releases**
- Milestones map to phases: `v0.1` (Phase 0) … `v1.0` (Phase 5).
- At the end of each phase, after PR merge: annotated tag + GitHub release.
  ```bash
  git tag -a v0.1.0 -m "Phase 0: lab foundation & telemetry pipeline"
  git push origin v0.1.0
  gh release create v0.1.0 --generate-notes
  ```

**Definition of "phase complete"**: all its issues closed · CI green · PR merged to `main` ·
`PROGRESS.md`/`README.md`/`CHANGELOG.md` updated · tag + release pushed · **then pause and report.**

---

## 5. Bootstrap the issue backlog (run first, once)

Save as `scripts/bootstrap-issues.sh`, review, then run. It creates labels, milestones, and every
issue. After this, the agent just works the queue.

```bash
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
```

---

## 6. Phase execution detail

Each phase below is: **goal → the issues (Section 5 has full AC) → phase verification → git actions.**
The agent should not need more than `DESIGN.md` + this section to execute a phase.

### Phase 0 · Lab foundation → milestone v0.1
- **Goal:** a working telemetry pipeline — attacks on a victim show up as queryable events in Wazuh.
- **Issues:** scaffolding · host prep · Wazuh compose · victim + telemetry.
- **Phase verification:** on the victim, run `sh -c 'id; whoami'`; within 30s the corresponding
  process event is returned by a Wazuh API query. Paste the query + result into the last issue.
- **Git:** branch `phase-0/lab-foundation` → PR → merge → `v0.1.0` tag/release → **pause & report.**

### Phase 1 · MVP loop → v0.2
- **Goal:** one technique, fully automated, produces a proof chain.
- **Issues:** model · WazuhCollector · Executor · Evaluator · wire CLI.
- **Phase verification:** `purpleloop run --technique T1059.004` prints a valid `ProofChain` JSON
  with a verdict and `evidence[]` populated on DETECTED.
- **Git:** branch `phase-1/mvp-loop` → PR → merge → `v0.2.0` → pause & report.

### Phase 2 · Engine & reports → v0.3
- **Goal:** drive a multi-technique campaign and emit reports.
- **Issues:** feed iface · orchestrator · reporter · Navigator export · seed techniques.
- **Phase verification:** `purpleloop run --plan discovery.yml` produces `reports/coverage.html`
  and a Navigator layer; HTML shows per-technique verdicts and totals.
- **Git:** `phase-2/engine-reports` → PR → merge → `v0.3.0` → pause & report.

### Phase 3 · CI & Windows → v0.4
- **Goal:** detection-as-code CI green; cross-platform coverage.
- **Issues:** fixtures + sigma lint · regression harness · Windows victim · Windows executor.
- **Phase verification:** an intentionally broken rule fails CI and a fix makes it pass; a Windows
  technique runs to a verdict.
- **Git:** `phase-3/ci-windows` → PR (CI must be green) → merge → `v0.4.0` → pause & report.

### Phase 4 · Arbiter integration → v0.5  *(the headline)*
- **Goal:** campaigns ordered by real threat-intel-arbiter priority; risk-driven report.
- **Issues:** arbiter feed adapter · CVE→technique→atomic mapping · priority campaign + narrative.
- **Phase verification:** feed a sample arbiter export; the run executes in priority order and the
  report leads with the exploited-in-the-wild coverage headline.
- **Reconcile point:** confirm the arbiter's actual output schema (score field name, technique
  mapping) and adapt the adapter — flag to the human if the schema differs from assumptions.
- **Git:** `phase-4/arbiter-integration` → PR → merge → `v0.5.0` → pause & report.

### Phase 5 · Emulation & release → v1.0
- **Goal:** multi-stage actor emulation + a polished, documented v1.0.
- **Issues:** plan format + runner · one actor plan · v1.0 polish & release.
- **Phase verification:** an actor plan runs end-to-end with per-actor coverage; README lets a
  newcomer run the project.
- **Git:** `phase-5/emulation-release` → PR → merge → `v1.0.0` + release → **report project complete.**

---

## 7. Environment constraints (bake these in)

- **Machine:** i7-11800H (8c/16t), 32 GB, NVMe SSD, dedicated to the lab.
- **Wazuh indexer:** JVM heap fixed at `-Xms4g -Xmx4g`; container memory limit ~8 GB.
- **Windows VM (Phase 3):** 4 vCPU, 6–8 GB.
- **Required host tweak:** `vm.max_map_count=262144` (persisted) — indexer won't start otherwise.
- **Retention:** 7-day index lifecycle so the indexer doesn't grow unbounded.
- **Thermal note:** sustained all-core load may throttle turbo on this mobile chip — that's expected,
  not a resource fault. Keep it plugged in. Do not "fix" throttling by changing host config.

---

## 8. Kickoff prompt (paste this to the agent — the only inline text needed)

> You are the build agent for **Purple Loop**. The full plan lives in the repo.
>
> 1. Open the repo `github.com/jayelbotvibe-web/purple-loop`. Read `AGENT_PLAYBOOK.md` and
>    `DESIGN.md` **in full** before acting. Summarise the plan and the operating contract back to me
>    in ~8 bullets so I know you've got it.
> 2. If the issue backlog doesn't exist yet, review and run `scripts/bootstrap-issues.sh`
>    (Playbook §5), then confirm the milestones and issues were created.
> 3. Follow the **Operating Contract** (§2) and **Git workflow** (§4) exactly. Work **one issue at a
>    time** from the lowest open milestone (start at **v0.1**). Restate your plan in the issue,
>    make small conventional commits referencing the issue, run each **verification** before moving on,
>    and update `PROGRESS.md`.
> 4. Respect **lab containment** (§3) and all **stop-and-ask** conditions (§2). When in doubt, stop and
>    report — don't improvise around a blocker or expand scope silently.
> 5. At the **end of each phase**, open a PR, ensure CI is green, tag the release, then **pause and
>    report to me** before starting the next phase.
>
> Begin now: read the two documents, give me your summary, then start with the first open issue in v0.1.

---

## 9. How the human knows the plan is on track

- **GitHub milestones** show phase progress at a glance (issues closed / total).
- **`PROGRESS.md`** is the running log — one line per completed issue with a commit hash.
- **Tags/releases** (`v0.1.0` … `v1.0.0`) mark each verified phase.
- **The pause-and-report gate** at every phase boundary means you review before the agent proceeds —
  the plan can't run away from you.
