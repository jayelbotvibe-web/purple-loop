# Progress log

One line per closed issue: date · issue · what shipped · verification · commit.

- 2026-07-04 · seed · starter kit committed (skeleton compiles & runs dry) · `go run ... --dry-run` prints proof chain · <hash>
- 2026-07-04 · #1 · repo scaffolding verified: `go build` passes, tree matches DESIGN.md, branch pushed · AC1-3 all pass · c2f5973
- 2026-07-04 · #2 · host prep: vm.max_map_count=1048576 (≥262144), docker compose 2.40.3, 275GB free · AC1-3 pass · cc408cb
- 2026-07-04 · #3 · Wazuh single-node up: indexer green, API token, dashboard 302 · fixes: versions.env quoting, build scope, verify-lab passwords+names · abd7e45
- 2026-07-04 · #4 · victim enrolled (ID 001, active), 190 events in alerts.json, API query documented in README · 009fb75
- 2026-07-04 · #5 · model test: ProofChain JSON shape verified against DESIGN.md §4 · go test PASS · 088d30d
