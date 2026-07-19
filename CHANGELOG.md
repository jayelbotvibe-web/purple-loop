# Changelog
All notable changes to this project follow Keep a Changelog and Semantic Versioning.

## [Unreleased]
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
