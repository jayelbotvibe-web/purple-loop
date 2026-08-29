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
for the techniques being exploited right now — the CISA KEV list, the CVEs making headlines. Purple
Loop closes that loop: given a prioritized list of ATT&CK techniques (from the
[threat-intel-arbiter](https://github.com/jayelbotvibe-web/threat-intel-arbiter)), it emulates
them in an isolated lab, collects real telemetry, evaluates the Sigma
rules, and produces an evidence-backed coverage report. No guessing, no presence-based fake numbers.

## How it works

![Pipeline diagram](docs/evidence/pipeline-diagram.png)

*[More detailed view → Interactive Architecture Map](https://jayelbotvibe-web.github.io/purple-loop/)*

1. **Feed** loads techniques from a plan, arbiter export, or emulation script
2. **Resolve** turns each `atomic_id` into a real command from the pinned Atomic Red Team
   tree — strictly. An unresolvable ID, or one whose atomic does not support the target
   platform, is an `ERROR` naming the problem, never a substituted default command
3. **Execute** runs that atomic on the lab victim (Docker Linux + VMware Windows)
4. **Collect** queries Wazuh archives for raw telemetry in the execution window
5. **Evaluate** normalizes events and matches them against Sigma rules using a native Go parser
6. **Report** produces JSON, HTML coverage grid, or ATT&CK Navigator layer export

## Pipeline canary (positive control)

Before any real techniques run, Purple Loop fires a **pipeline canary** — a known-benign command
engineered to be trivially detectable. It proves the full pipeline (execute → telemetry → collect →
normalize → match) is healthy, *per platform*, before trusting any campaign result.

```bash
make canary
# Canary marker: purpleloop-canary-a1b2c3d4
# Canary: DETECTED on windows (evidence: 4 events)
```

**Behavioral contract:**
- **Canary DETECTED** → pipeline is healthy; every `MISSED` in that run is a genuine detection gap
- **Canary NOT detected** → run is `INCONCLUSIVE`; coverage is not reported; pipeline is broken

This removes the ambiguity that caused v1.0's false 100% coverage — you can now trust your gaps.

## Results  *(v1.2 — real Sigma matching, not presence-based)*

![Sample coverage result](docs/evidence/sample-result.png)

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

### Precision, not just coverage

```bash
purpleloop precision
# Precision: 100%  (26 benign commands, 10 rules)
```

Coverage answers *does it fire when it should*. Precision answers *does it stay quiet when it
should* — a rule matching everything scores perfect coverage and is worthless. Every detection
is measured against a benign administrator workload including **adjacent cases**: benign uses
of the very binaries the rules watch. This found two real false positives on introduction
(`T1087.001` fired on `getent hosts`, a DNS lookup; `T1135` fired on a bare `mount`), and both
rules were narrowed. It exits non-zero, so it gates CI.

### Replay a captured run — no lab required

```bash
purpleloop replay testdata/sample-run
```

Every real run writes `reports/runs/<id>/events.jsonl`. `replay` re-runs the **real** evaluator
over that telemetry with no Docker and no Wazuh, so a rule edit can be checked against every
past run: *would this have broken a detection that already worked?* CI runs it on every push.

### Compare two runs

```bash
purpleloop diff reports/runs/<older> reports/runs/<newer> --fail-on-regression
# REGRESSED (1)
#   T1082        DETECTED -> MISSED
```

Run: `purpleloop serve` for a **local web dashboard** with all past runs at `http://127.0.0.1:8787`.

[Live dashboard on GitHub Pages](https://jayelbotvibe-web.github.io/purple-loop/dashboard.html).

## Quickstart

```bash
git clone https://github.com/jayelbotvibe-web/purple-loop.git && cd purple-loop
make atomics          # vendor Atomic Red Team at the pinned commit — required
bash scripts/startup.sh
```

Bringing the lab up by hand needs one extra step, because the collector reads the manager's
full event archive rather than only rule-triggered alerts:

```bash
make lab-up
make archives   # enable <logall_json>; without it EVERY technique reports NO_TELEMETRY
make verify     # health gates + pipeline canary
```

Full guide: [STARTUP.md](STARTUP.md) — covers lab, Windows VM, arbiter connection, campaigns, troubleshooting.

```bash

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
the arbiter ingests MISP/KEV feeds, scores threats with SSVC, maps them to ATT&CK techniques,
and exports a priority-ordered plan. Purple Loop executes that plan — emulating each technique in
the lab and validating whether the corresponding behavioral (TTP) detection fires. Indicator-level
(IOC) matching is out of scope; the arbiter passes techniques, not hashes or IPs.

[`threat-intel-arbiter → arbiter-live.json → purple-loop run --arbiter`]

## Atomic resolution and lab overrides

Every technique's command comes from the Atomic Red Team commit recorded in
`mappings/atomic-red-team.commit`, checked out and **verified** by `make atomics`. Resolution
is strict: `override → vendored ART → error`. There is deliberately no default command — a
fabricated input produces a fabricated verdict, so an atomic that cannot be resolved fails
loudly instead.

Three verdicts exist for "this never tested a detection", and none of them counts toward
coverage:

| Verdict | Means |
|---|---|
| `ERROR` | The atomic could not be resolved, or does not support the target platform |
| `SKIPPED_PREREQ` | The atomic's own `prereq_command` failed — it never ran |
| `NO_TELEMETRY` | It ran, but the events the rule needs never arrived |

`mappings/atomic-overrides.yml` adjusts atomics that cannot run truthfully in this lab. Every
entry requires a `reason`, which appears in the report, so a substitution is never mistaken for
the upstream atomic. Two kinds, narrower preferred:

- **Pinned inputs** keep the upstream command and override only its declared inputs. Used for
  containment — upstream `T1059.004-1` pings `8.8.8.8`, which leaves the isolated lab network,
  so `host` is pinned to loopback.
- **Replaced commands** substitute the atomic wholesale, only where no usable upstream test
  exists. `T1518` (Software Discovery) has six atomics and not one supports Linux.

## Design decisions / scope

**Behavioral (TTP) validation, by design.** Purple Loop validates ATT&CK technique
detections, not individual indicators. This is intentional: on the Pyramid of Pain,
hashes and IPs are trivial for an adversary to change, while TTPs are costly — so
validating technique coverage is the durable, higher-value target. IOC-level validation
(e.g., network indicators against a lab sinkhole) is a possible future track, but is out
of scope today; a hash "check" would be a content-coverage lookup, not a real detection test.

CISA KEV and MISP inform which ATT&CK techniques to prioritize; Purple Loop then validates
the behavioral detections for those techniques — indicator-level (IOC) matching is out of scope.

## Architecture

Full architecture in [DESIGN.md](DESIGN.md). The engine is built on five pluggable Go interfaces:
`Executor`, `Collector`, `Evaluator`, `Feed`, `Reporter` — swap any component without changing the
orchestrator. Lab runs isolated on `purpleloop-lab` Docker network.

## Detection-as-code

Every Sigma rule has **positive + negative fixtures**, and each rule detects what its own
technique's atomic actually does. CI enforces:
- All positives must match, all negatives must reject
- **No two rules may share detection logic** — a campaign whose detections are one rule under
  many names reports coverage it does not have
- Every rule is mapped to a technique or explicitly declared untested **with a reason**
- Every rule stays silent on the benign workload (`purpleloop precision`)
- `sigma check` (pySigma) validates against the Sigma spec, not just this repo's parser
- A broken rule fails `go test ./cmd/... ./internal/...` and turns CI red

```bash
go test ./internal/evaluator/ -v -run Regression
# Regression: 10 rules tested, all positive/negative fixtures correct
```

## Supported Sigma subset

The native Go matcher supports the Sigma specification subset needed for process-creation rules:
field modifiers (`contains`, `startswith`, `endswith`, `|all`, `re`, numeric `lt`/`lte`/`gt`/`gte`),
`*` wildcards in values, keyword (full-text) search identifiers, condition grammar
(`and`/`or`/`not`/parens/`1 of them`/`all of them`), and case-insensitive matching. Not yet
supported: aggregation expressions, `near`, correlated rules, `base64`/`cidr` modifiers.

**Evidence fidelity.** For `process_creation` rules the evaluator only accepts genuine
process-creation telemetry (Sysmon/EventChannel `eventdata`, auditd `execve`). Command-output and
metadata scrapes (`full_log`, decoder name) are tagged low-fidelity and can never satisfy a
process-creation rule — so a log line that merely mentions a binary cannot produce a false
`DETECTED`. When a technique collects only low-fidelity events, the verdict is `NO_TELEMETRY`
(a collection gap), not `MISSED`.

## Limitations

- **Lab-contained only.** Never run against production or targets outside `purpleloop-lab`.
- **Linux Sysmon gap.** The Linux victim has command-output telemetry but not Sysmon process-creation events. This is a known gap; Windows Sysmon detection is confirmed working.
- **Collection gaps hand off to [detection-decay](https://github.com/jayelbotvibe-web/detection-decay).** A `NO_TELEMETRY` verdict is the symptom — the rule never saw the events it needs. detection-decay models the cause (source death, field drift). Every run emits `collection_gaps` naming the technique and the rules whose fields went missing.
- **One atomic per technique.** A technique runs the first atomic its plan or the rule map names. Exercising several per technique is not yet supported.
- **SSVC mapping.** The arbiter uses pre-SSVC labels (Schedule/Monitor/Track) mapped to SSVC v2.1 equivalents.
- **Coverage denominator.** Coverage is measured over techniques that actually exercised a
  detection. `ERROR`, `SKIPPED_PREREQ`, `NO_TELEMETRY` and `INCONCLUSIVE` are reported
  separately rather than counted as gaps — a harness failure is not a detection gap.

## License

MIT — see [LICENSE](LICENSE).
