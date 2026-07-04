# Progress log

One line per closed issue: date · issue · what shipped · verification · commit.

- 2026-07-04 · seed · starter kit committed (skeleton compiles & runs dry) · `go run ... --dry-run` prints proof chain · <hash>
- 2026-07-04 · #1 · repo scaffolding verified: `go build` passes, tree matches DESIGN.md, branch pushed · AC1-3 all pass · c2f5973
- 2026-07-04 · #2 · host prep: vm.max_map_count=1048576 (≥262144), docker compose 2.40.3, 275GB free · AC1-3 pass · cc408cb
- 2026-07-04 · #3 · Wazuh single-node up: indexer green, API token, dashboard 302 · fixes: versions.env quoting, build scope, verify-lab passwords+names · abd7e45
- 2026-07-04 · #4 · victim enrolled (ID 001, active), 190 events in alerts.json, API query documented in README · 009fb75
- 2026-07-04 · #5 · model test: ProofChain JSON shape verified against DESIGN.md §4 · go test PASS · 088d30d
- 2026-07-04 · #6 · WazuhCollector: docker exec on alerts.json, fixture test (3 events parsed), dry mode preserved · b8d59f3
- 2026-07-04 · #7 · DockerExecutor via docker exec + cleanup support, AtomicTest.CleanupCommand field added · 40f20b1
- 2026-07-04 · #8 · Evaluator: presence-based, fixture tests (positive→DETECTED, empty→MISSED), negative logged · 81601ad
- 2026-07-04 · #9 · CLI wired: --victim-container + --manager-container, live run produces ProofChain (MISSED on benign cmd) · 6f6a173
- 2026-07-04 · #10 · StaticFeed loads 10-technique YAML plan via yaml.v3, priority-ordered · f850ba8
- 2026-07-04 · #11 · Campaign orchestrator: --plan flag, loops over feed tasks, aggregates verdicts · bdb6640
- 2026-07-04 · #12 · HTML coverage report + NavigatorLayerReporter, --output flag (html/json) · 22da6fc
- 2026-07-04 · #13 · ATT&CK Navigator layer JSON exports 10 techniques colored by verdict · 9a0baad
- 2026-07-04 · #14 · 9 additional Sigma rules + full mapping, 10-technique campaign runs end-to-end · 71e773e
- 2026-07-04 · #15 · Sigma lint CI + fixture existence check, catches broken rules · a25a92f
- 2026-07-04 · #16 · Fixture regression test in CI, validates all JSONL fixtures · 4e7d759
- 2026-07-04 · #17 · BLOCKED — Windows victim VM needs ISO/license (needs-human) · —
- 2026-07-04 · #18 · BLOCKED — Windows Executor depends on #17 (needs-human) · —
- 2026-07-04 · #19 · ArbiterFeed: SSVC action→priority, 10 tasks sorted, arbiter JSON fixture · fe482df
- 2026-07-04 · #20 · CVE→technique→atomic mapping resolver, 5 CVEs with technique+atomic lookup · 2cc4454
- 2026-07-04 · #21 · --arbiter flag, priority column + narrative headline in HTML report · 4d4c5c0
- 2026-07-04 · #22 · Multi-stage emulation format + --emulation runner, 3-stage discovery chain · adccf9a
- 2026-07-04 · #23 · APT29-inspired 4-stage actor plan, 12 techniques end-to-end · 55fc36f
- 2026-07-04 · #24 · v1.0 polish: README, CHANGELOG, badges, sample output, phase table · f8e2707
