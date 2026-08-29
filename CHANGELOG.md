# Changelog
All notable changes to this project follow Keep a Changelog and Semantic Versioning.

## [Unreleased]

## [2.0.0] — 2026-08-29

### Breaking
- **Coverage is measured only over techniques that actually exercised a detection.**
  `INCONCLUSIVE`, `NO_TELEMETRY`, `SKIPPED_PREREQ` and `ERROR` are reported separately instead
  of counting as gaps, so published percentages will move — a harness failure is not a
  detection gap.
- **New verdict `SKIPPED_PREREQ`.** Anything parsing verdicts must handle it.
- **`mappings/attack_rule_map.seed.json` is removed**, replaced by
  `mappings/attack_rule_map.json` with a different schema (`techniques` / `untested_rules`, and
  `expected_rules[]` per technique).
- **`lab/targets.yml` is required** for `run` and `canary`, and declares no default Windows
  address. With `WINDOWS_SSH_HOST` unset, `canary` now errors instead of probing 192.168.88.13.
- **`make atomics` is required before any run.** The engine resolves every command from the
  pinned Atomic Red Team tree and has no fallback.
- Plan and emulation files name different atomic IDs (the Linux tests, not ART's first test).

### Fixed (2026-08 review — the engine now executes the atomics it claims to)
- **Every technique ran the same hardcoded `id; whoami`.** `atomic_ids` was parsed from plan
  YAML, carried through emulation stages and the arbiter feed and written into the proof
  chain — but never resolved to a command. A ten-technique campaign ran one command ten times
  and labelled the results T1082, T1033, T1518… so every verdict but `T1059.004`'s was about a
  command nobody asked for. The README's claim that Execute "runs Atomic Red Team tests" was
  not true of the code. New `internal/atomic` package resolves each `atomic_id` against the
  pinned ART tree; resolution is strict (`override → vendored ART → error`) and there is no
  default command.
- **Five of ten techniques in `plans/discovery.yml` named Windows atomics** while the campaign
  targets a Linux victim (`T1082-1`, `T1033-1`, `T1007-1`, `T1016-1`, `T1049-1` are all
  `command_prompt` tests). Invisible while everything ran `id; whoami`. Plans and emulation
  chains now name the correct Linux tests, and a platform mismatch is a loud `ERROR`.
- **Containment breach in the pinned atomics.** `T1059.004-1` writes a script that pings
  `8.8.8.8` — traffic leaving the isolated lab network, against the project's own rule. Its
  `host` input is pinned to loopback via an override that keeps the upstream command.
- **`ERROR` was counted as `missed`** in the HTML headline, and `SKIPPED_PREREQ`/`ERROR` were
  inside the dashboard's coverage denominator. A harness failure is not a detection gap;
  coverage is now measured only over techniques that actually exercised a detection.
- **Atomic Red Team was recorded, not pinned.** `lab-fetch.sh` cloned HEAD then overwrote the
  pin file with whatever it got, so a re-clone could silently change every command the engine
  runs. `scripts/fetch-atomics.sh` checks out the recorded commit and verifies HEAD matches.
- Dashboard no longer hardcodes `campaign: "discovery"` and `build: "v1.3.0"`; both come from
  the run. `gap.why` is populated from the verdict's note instead of always being empty.
- `make help` printed "Makefile" in place of every target name (`grep` needed `-h`).

### Fixed (2026-08 — the detections had the same defect as the engine)
- **Nine of the ten Linux Sigma rules were the identical rule.** Every one matched
  `Image endswith /id or /whoami`, differing only in title, because they were written against
  an engine that executed `id; whoami` for every technique. All nine shared one byte-identical
  positive fixture, so the "10 rules, 20 fixtures, CI enforced" detection-as-code claim was
  testing one rule nine times against one event. Each technique now has a detection for what
  its own atomic actually does, with distinct fixtures whose negatives include a *neighbouring*
  technique's activity — so a rule that is secretly a copy fails its own negative test.
- **Two false positives found by the new precision gate and fixed**: `T1087.001` fired on
  `getent hosts localhost` (a DNS lookup, not account enumeration) and `T1135` fired on a bare
  `mount`. Both rules keyed on a tool name rather than what the tool was being asked to do.
- **`win_proc_create.yml` had a non-UUID identifier** (`win-proc-create-001`), a Sigma spec
  violation the hand-rolled Go parser accepted silently. Found by adding `sigma check`.
- **The Windows path was unreachable from `run`.** `runTasks` hardcoded a Linux target, rules
  directory and executor; `SSHExecutor` and the Windows rule existed only inside the standalone
  `canary` subcommand, which also hardcoded the IP `192.168.88.13`. Targets are now declared in
  `lab/targets.yml`, techniques are dispatched by the platform their rule-map entry names, and
  the canary runs once per platform in use — a healthy Linux canary says nothing about whether
  Windows telemetry is flowing.
- **`history.json` stored only a coverage percentage**, so no run could be compared with
  another. It now carries per-technique verdicts, which is what `purpleloop diff` needs.

### Fixed (2026-08 — lab reproducibility)
- **Archive logging did not survive a restart.** The collector reads
  `archives.json`, which the manager only writes when `<logall_json>` is `yes`; the image ships
  it as `no`. It had been enabled by hand *inside the running container*, which cannot work:
  the manager bind-mounts `/wazuh-config-mount/etc/ossec.conf` from the host and its entrypoint
  copies that over `/var/ossec/etc/ossec.conf` on every start, so the edit is wiped by the very
  restart needed to apply it. The stack then comes up healthy, the agent enrolls, and every
  technique reports `NO_TELEMETRY` — which reads as a detection problem and is not one.
  `scripts/enable-archives.sh` (`make archives`) patches the host-side source of the config
  mount and then *verifies* the setting is live inside the container.

### Fixed (2026-08 — victim telemetry honesty)
- **The victim entrypoint hid a total telemetry failure.** It ran
  `service auditd start || auditd || true`, so every failure was swallowed: the container came
  up looking healthy with no process-creation source at all, and the pipeline then reported
  `NO_TELEMETRY` for every technique — which reads as a detection problem and is not one. The
  entrypoint now probes the kernel audit subsystem, loads `execve` rules when it is usable, and
  otherwise says loudly that this victim has no process-creation telemetry and that runs will
  be `INCONCLUSIVE` as a result.
- **`--settle-timeout` / `--settle-poll` are configurable.** The 60s default is below the
  victim's 360s `<localfile>` collection interval, so even command-output telemetry could not
  land inside a technique's window. Documented on the flag itself.
- Verified and documented in `docs/PITFALLS.md` what actually blocks Linux process-creation
  telemetry: auditd is impossible on a host whose kernel exposes no audit sysctls (reproduced
  with `--privileged --network host`), and Sysmon for Linux only runs under systemd (its
  `-service` mode still shells out to `systemctl`). Closing the gap needs a systemd-based
  victim — a deliberate change to the lab's security posture, not a config tweak.

### Added (2026-08 — Linux-Sysmon readiness)
- Normalizer handles a `data.sysmon` path: Linux-Sysmon `EventID 1` is treated as genuine
  process creation, any other Sysmon event ID is low fidelity and can never satisfy a
  `process_creation` rule. Events are deliberately not routed through `data.win.*`, which is
  Wazuh's Windows eventchannel convention. Tested in `internal/evaluator/sysmon_linux_test.go`,
  including that a non-creation event with identical fields does not match.
- Documented in `docs/PITFALLS.md` why the Linux victim is a container without process-creation
  telemetry rather than a container running Sysmon: Sysmon for Linux works, but its eBPF is
  kernel-global and the event carries no container identity, so scoping it either leaks host
  processes (PID reuse) or drops the atomics' own short-lived ones. Both manufacture false
  verdicts. The fix is a Linux VM, as the Windows victim already is.

### Added (2026-08)
- `purpleloop precision` and `internal/precision`: measures the false-positive rate against a
  benign administrator workload (`emulation/benign-baseline.yml`, 26 commands across 7
  categories) including adjacent cases — benign uses of the binaries the rules watch. Exits
  non-zero on any false positive, so it gates CI.
- `purpleloop replay` and `internal/capture`: every real run writes
  `reports/runs/<id>/events.jsonl`; replay re-runs the real evaluator over it with no lab. CI
  replays `testdata/sample-run` on every push, so rule edits are checked against telemetry
  rather than only against fixtures written to match them. The capture writer refuses synthetic
  runs, whose "telemetry" is fabricated.
- `purpleloop diff <a> <b> [--fail-on-regression]`: names the technique that regressed
  (`T1082 DETECTED -> MISSED`) instead of only moving a percentage. Verdicts that mean "never
  exercised" share a rank, so ERROR -> SKIPPED_PREREQ is a change, not a regression.
- `collector.Settler`: polls until an expected rule matches or ingestion settles, replacing the
  fixed `time.Sleep(10s)` per technique and its 10-minute query window.
- Attribution labels on every verdict (`window_and_host_scoped`, `window_scoped`,
  `window_overlap`, `unscoped`) and `detect_latency_ms`. Overlap is computed campaign-wide once
  every window is known. This changes no verdict; it states the quality of the evidence behind
  one.
- `mappings/attack_rule_map.json` with `expected_rules[]` — a technique is DETECTED when ANY
  expected rule matches. Replaces the technique->rule map hardcoded in `cmd/purpleloop`.
- `untested_rules` accounting: every rule is mapped to a technique or declared untested with a
  reason, enforced by a CI lint, and reported per run.
- `collection_gaps` in the dashboard output, naming the technique and rules behind each
  `NO_TELEMETRY`, for handoff to the sibling detection-decay repo.
- `lab/targets.yml` + `internal/lab`, `plans/windows-discovery.yml`, `plans/cross-platform.yml`.
- `make archives` / `scripts/enable-archives.sh`.
- `sigma check` (pySigma) in CI, and a `gofmt` gate. CI now runs `./cmd/...` too — the
  atomic-resolution, attribution, replay and diff guards live there and were being skipped.
- Regression guards for both halves of the defect: no two techniques in a campaign may resolve
  to the same command, and no two rules may share detection logic.

### Added (2026-08, atomics)
- `internal/atomic`: ART loader with input-argument interpolation, prerequisite parsing,
  platform support checks and lab overrides.
- `SKIPPED_PREREQ` verdict — an atomic whose own prerequisites are unmet never ran, and is no
  longer reported as a detection miss.
- `mappings/atomic-overrides.yml`: two override kinds — pinned inputs (keeps the upstream
  command, used for lab containment) and replaced commands (only where no usable upstream test
  exists). Every entry requires a `reason`, which the loader enforces and the report shows.
- Proof chains carry atomic provenance (`name`, `guid`, `source`, `override_reason`) and a
  `note` explaining any non-coverage verdict. Campaign results record the ART commit.
- `make atomics` target and `scripts/fetch-atomics.sh`.
- Regression guard: a test fails if any two techniques in the shipped campaign resolve to the
  same command — the defect above, made unshippable.

### Fixed (2026-07 code review — trust contracts enforced in code, not just docs)
- **Canary gating now runs in the pipeline.** Every `run` path executes the positive
  control against the same Linux/Docker executor+collector the campaign uses; if it does
  not fire, the run is marked `INCONCLUSIVE` and its coverage is not presented or published.
  Previously the canary ran only in the standalone `canary` subcommand and no `run` was ever
  gated.
- **Dashboard canary status is the real result**, never hardcoded `healthy:true`.
- **Dry/synthetic runs are marked non-evidentiary end to end** (`CampaignResult.Synthetic`):
  loud banner in the HTML/Navigator output, and such runs are never appended to `history.json`
  or published to `docs/data/coverage.json`.
- **Partial container config is rejected** — a real run requires both `--victim-container`
  and `--manager-container` (or `--dry-run`), so a real atomic is never paired with a
  synthetic collector.
- **Fidelity gate corrected**: only genuine process-creation events (Sysmon 1 / Security 4688,
  or the image+commandLine signature) are treated as process telemetry. Enumeration/network
  events (e.g. 4798 `callerProcessName`) no longer credit a process-creation detection.
- **Unsupported Sigma modifiers** (base64, cidr, windash, …) now yield `INCONCLUSIVE`, not a
  silent `MISSED`.
- **Sigma matcher correctness**: wildcards compile to anchored regexps (`?` supported,
  `*\svchost.exe` no longer matches `…svchost.exe.malware`, metacharacters escaped);
  `N of prefix_*` / `all of prefix_*` expand by glob and no longer drop the trailing
  `and not filter`; `Field: null` matches absent fields; `not(...)` (no space) parses; `of
  them` excludes filter/falsepositive identifiers.
- **Evidence window** pads only the end (ingestion lag), not the start — a query can no
  longer reach back and credit an earlier run's events (false `DETECTED`).
- **Collector date pre-filter** widened ±1 day so a non-UTC Wazuh timestamp near a day
  boundary is not dropped before the precise instant check.
- Removed the hardcoded `admin:SecretPassword` from `scripts/verify-lab.sh` (now sourced from
  env / the gitignored secrets file, matching the manager check). Removed dead
  `BaseURL`/`User`/`Pass` collector fields and the unused `canary.Check` dry-run parameter.

### Added
- Evidence fidelity: normalizer tags each event's source; `process_creation` rules now
  only accept genuine process-creation telemetry (Sysmon/EventChannel eventdata, auditd
  execve). Low-fidelity `full_log`/decoder scrapes can no longer produce a false `DETECTED`.
- Sigma matcher coverage: `re` (regex), numeric `lt`/`lte`/`gt`/`gte`, and keyword
  (full-text search) identifiers.
- Wazuh collector date pre-filter: queries read only the day(s) a window spans instead of
  the whole archive; scanner buffer enlarged so long archive events are no longer truncated.
- Unit tests for the previously untested `canary` and `report` packages.
### Changed
- Canary now executes once and polls telemetry until a deadline (configurable via `Checker`)
  instead of re-firing on fixed-interval retries.
- Techniques whose collected events are all low-fidelity report `NO_TELEMETRY` (collection
  gap) rather than `MISSED` (proven detection miss).
- Dry-run / synthetic pipeline prints an unmistakable banner so its output cannot be mistaken
  for real telemetry.

## [1.2.0] — 2026-07-04
### Added
- Pipeline canary (positive control): per-run marker, gating logic, `make canary`
- Windows Sysmon Event ID 1 telemetry via Wazuh agent channel forwarding
- Windows Sigma rule (`win_proc_create.yml`) with positive/negative fixtures
- GitHub Pages architecture plan (`docs/index.html`)
- SECURITY.md, CONTRIBUTING.md, RESULTS.md
- Repo About metadata: 15 topics, description, homepage

### Changed
- Normalizer handles `data.win.eventdata` fields (image, commandLine, parentImage, user)
- `make verify` now includes pipeline canary gate
- README overhaul: badges, architecture, canary section, honest results
- Release notes rewritten for v1.0.0 and v1.1.0

### Fixed
- v1.1 0/10 coverage: Linux lacked process-creation telemetry; Windows now DETECTED
- Canary removes ambiguity between "pipeline broken" and "genuine detection gap"

## [1.1.0] — 2026-07-04
### Added
- Real Sigma rule parser + native Go matcher (field modifiers, condition grammar)
- Event normalizer: Wazuh JSON → canonical Sigma fields (Image, ParentImage, CommandLine, User)
- RuleMatcherEvaluator replacing presence-based evaluation
- NO_TELEMETRY verdict — distinguishes collection failure from detection gap
- CI regression test: 10 rules, 20 fixtures, all positives match + negatives reject

### Changed
- Verdict semantics: DETECTED=rule matched, MISSED=events but no match, NO_TELEMETRY=no events
- Proof-chain integrity: rule_matched empty unless matched, evidence = matching events only
- Dry-run event matches the sample Sigma rule for pipeline validation

### Fixed
- Integrity gap: v1.0 "100% DETECTED" was presence-based (any events=detected), not rule-based

### Known Gap
- Live lab: 10/10 MISSED — telemetry sources (command output, SCA, Event Channel) lack
  process-creation fields (Image, ParentImage). Sysmon process creation (Event ID 1) needed
  for real detection evaluation.

## [1.0.0] — 2026-07-04
### Added
- Multi-stage actor emulation plans (discovery-chain, APT29 subset) with `--emulation` flag
- Arbiter feed adapter: SSVC action→priority, `--arbiter` flag, CVE→technique→atomic mapping
- HTML coverage report with priority column, CVE tracking, narrative headline
- ATT&CK Navigator layer JSON export (verdict-colored techniques)
- Detection-as-code CI: sigma lint + fixture regression tests
- 10 Sigma rules with positive/negative fixtures
- 10-technique discovery campaign plan
- Campaign orchestrator with `--plan` flag
- Live lab execution: DockerExecutor (docker exec), WazuhCollector (archives.json)
- SSHExecutor for Windows victims via key-based SSH
- Windows 11 victim: Wazuh agent + Sysmon, 183+ events flowing
- Real ProofChain output with DETECTED verdict + evidence from live lab
- Test suite: 9 tests across 6 packages

### Changed
- Collector uses archives.json (all events) instead of alerts.json (rule-triggered only)
- 10-minute telemetry window with 10-second ingest delay for reliable event capture
- Go build/vet scoped to `./cmd/... ./internal/...`

### Fixed
- INDEXER_HEAP quoting in versions.env for Make compatibility
- verify-lab.sh container name resolution and indexer password
- Wazuh archives logging enabled for full event capture

## [0.1.0] — 2026-07-04
### Added
- Project scaffolding: Go skeleton with pluggable interfaces and dry-run loop
- Wazuh 4.9.2 single-node lab (indexer, manager, dashboard)
- Ubuntu 22.04 victim container with Wazuh agent + auditd
- Lab tooling: Makefile, host-prep, lab-fetch, verify-lab scripts
- CI: build, vet, gitleaks
- Guardrails: pre-commit hooks, issue/PR templates, pitfalls guide
