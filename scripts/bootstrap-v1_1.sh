#!/usr/bin/env bash
set -euo pipefail
R="jayelbotvibe-web/purple-loop"

gh label create "fix" -c "#FF5D73" -f 2>/dev/null || true
gh label create "evaluator" -c "#8B7CFF" -f 2>/dev/null || true
gh api repos/$R/milestones -f title="v1.1" -f description="Real detection evaluation" >/dev/null 2>&1 || true
iss(){ gh issue create -R "$R" -t "$1" -b "$2" -m v1.1 ${3:+-l "$3"}; }

iss "Sigma rule parser + native matcher" "Implement a minimal Sigma matcher (REMEDIATION §4). Parse a rule's detection block; evaluate search-identifiers with field modifiers (equals/contains/startswith/endswith, list OR, |all) and a condition grammar (and/or/not/parens, 1 of them, all of them). **AC:** unit tests over detections/tests/*/positive_events.jsonl all match, negatives all don't; 'go test ./internal/evaluator/...' PASS." "fix,evaluator"
iss "Event normalizer (Wazuh -> canonical fields)" "Map live Wazuh event JSON to canonical Sigma field names (Image, ParentImage, CommandLine, User). DERIVE field paths from REAL captured events (REMEDIATION §5). Cover linux (auditd/Sysmon-for-Linux) and windows (Sysmon). **AC:** a captured Linux event and a captured Windows event each normalize to non-empty Image/CommandLine; unit test with recorded event fixtures." "fix,evaluator"
iss "Wire rule-matching evaluator into the pipeline" "Replace PresenceEvaluator. Per technique, load ALL mapped rules, normalize each collected event, evaluate per §2 verdict semantics. Fix proof-chain integrity: rule_matched empty unless matched; evidence = only matching events; add NO_TELEMETRY when events_collected==0. Keep --dry-run working. **AC:** live lab run yields consistent rule_matched/evidence per §2." "fix,evaluator"
iss "Enforced detection regression test in CI" "A Go test asserts every rule MATCHES all its positive fixtures and MATCHES NONE of its negatives; CI fails otherwise. **AC:** intentionally break one rule -> 'go test ./...' fails and CI red; revert -> green." "fix,ci"
iss "Re-baseline coverage honestly" "Re-run discovery.yml and arbiter campaign with real evaluation. Record true numbers (expect <100%). Update README, reports/samples/, docs/evidence/, report narrative to lead with gap list. Purge 100% language from all docs. Update PROGRESS.md + CHANGELOG.md. **AC:** committed sample report shows realistic rate and named gaps." "fix,docs"
iss "Document evaluator honestly + limitations" "Update DESIGN.md/README evaluator sections: describe real Sigma matching, the §2 verdict table, normalization layer, and SUPPORTED Sigma subset. **AC:** reader can tell exactly how a verdict is produced and what the matcher does/doesn't handle." "fix,docs"

echo "v1.1 backlog created."
