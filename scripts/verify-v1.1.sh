#!/usr/bin/env bash
# v1.1 landing verification. Exit 0 only if all automated gates pass.
set -uo pipefail
pass=0; fail=0
ok(){ echo "  PASS  $1"; pass=$((pass+1)); }
no(){ echo "  FAIL  $1" >&2; fail=$((fail+1)); }

echo "== Gate 1: shipped =="
gh release view v1.1.0 >/dev/null 2>&1 && ok "v1.1.0 release exists" || no "no v1.1.0 release"

echo "== Gate 2: evaluator is real =="
grep -riq "presence" internal/evaluator/ && no "presence logic still present" || ok "no presence logic"
grep -riqE "condition|detection|endswith|unmarshal|readfile" internal/evaluator/ \
  && ok "evaluator parses/matches rules" || no "evaluator does not read rules"
v_none=$(go run ./cmd/purpleloop run --technique T9999 --dry-run 2>/dev/null | grep -oiE 'DETECTED|MISSED|NO_TELEMETRY' | head -1)
[ "$v_none" != "DETECTED" ] && ok "unmapped technique -> $v_none (not DETECTED)" || no "unmapped technique returned DETECTED (presence fallback!)"
v_hit=$(go run ./cmd/purpleloop run --technique T1059.004 --dry-run 2>/dev/null | grep -oiE 'DETECTED|MISSED|NO_TELEMETRY' | head -1)
[ "$v_hit" = "DETECTED" ] && ok "sample technique -> DETECTED" || no "sample technique did not DETECT ($v_hit)"

echo "== Gate 3: regression enforced =="
grep -q "go test" .github/workflows/ci.yml && ! grep -qE "go test.*(\|\| true|\|\| echo)" .github/workflows/ci.yml \
  && ok "CI runs go test for real" || no "CI test step missing or swallowed"
go test ./internal/... >/dev/null 2>&1 && ok "go test passes" || no "go test fails"
f=$(ls detections/linux/*.yml 2>/dev/null | head -1)
if [ -n "$f" ]; then cp "$f" /tmp/rule.bak; sed -i 's/endswith/startswith/g' "$f"
  if go test ./internal/... >/dev/null 2>&1; then no "regression NOT enforced (broken rule still passes)"; else ok "regression enforced (broken rule fails)"; fi
  cp /tmp/rule.bak "$f"; fi

echo "== Gate 4: honest numbers =="
grep -rniqE "100%|full coverage|10 ?/ ?10|10 detected / 0" README.md docs/ 2>/dev/null \
  && no "a 100%/10-of-10 claim remains" || ok "no 100% claims"

echo
echo "== SUMMARY: $pass passed, $fail failed =="
[ "$fail" -eq 0 ] && echo "v1.1 landed." || echo "v1.1 NOT verified — see FAILs above."
exit $fail
