# Changelog
All notable changes to this project follow Keep a Changelog and Semantic Versioning.

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
