package evaluator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// TestGlobMatch_Anchored guards the wildcard fixes: patterns are anchored to the
// whole value (no false DETECTED from trailing/leading slop) and `?` matches
// exactly one character.
func TestGlobMatch_Anchored(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{`*\svchost.exe`, `c:\windows\svchost.exe`, true},
		{`*\svchost.exe`, `c:\x\svchost.exe.malware`, false}, // trailing anchored
		{`cmd*`, `cmd.exe`, true},
		{`cmd*`, `xcmd.exe`, false}, // leading anchored
		{`C:\Users\?\evil.exe`, `C:\Users\a\evil.exe`, true},
		{`C:\Users\?\evil.exe`, `C:\Users\ab\evil.exe`, false}, // ? = one char
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.value); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.value, got, c.want)
		}
	}
}

// TestCondition_AggregateGlobHonorsTrailingFilter guards the P0 fix: `N of
// prefix_*` expands by glob AND the trailing `and not filter` is no longer
// dropped by the parser (which would lose filter suppression → false DETECTED).
func TestCondition_AggregateGlobHonorsTrailingFilter(t *testing.T) {
	expr, err := parseCondition("1 of selection_* and not filter")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	detections := map[string]FieldMap{
		"selection_a": {"Image": {Values: []string{"/bin/evil"}}},
		"filter":      {"User": {Values: []string{"root"}}},
	}
	// Matches selection_a AND filter → "1 of selection_*" true, "not filter" false.
	if evalExpr(expr, detections, map[string]string{"Image": "/bin/evil", "User": "root"}) {
		t.Error("filter should suppress via the trailing 'and not filter'")
	}
	// Matches selection_a, not filter → true.
	if !evalExpr(expr, detections, map[string]string{"Image": "/bin/evil", "User": "alice"}) {
		t.Error("selection matches and filter does not → should match")
	}
}

// TestMatchNull guards Sigma `Field: null` (match when absent/empty).
func TestMatchNull(t *testing.T) {
	expr, _ := parseCondition("sel")
	detections := map[string]FieldMap{"sel": {"CommandLine": {MatchNull: true}}}
	if !evalExpr(expr, detections, map[string]string{"Image": "x"}) {
		t.Error("Field: null should match when the field is absent")
	}
	if evalExpr(expr, detections, map[string]string{"CommandLine": "present"}) {
		t.Error("Field: null should NOT match when the field is present")
	}
}

// TestNot_NoSpaceBeforeParen guards `not(...)` (no space) parsing.
func TestNot_NoSpaceBeforeParen(t *testing.T) {
	expr, err := parseCondition("not(sel)")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	detections := map[string]FieldMap{"sel": {"Image": {Values: []string{"/bin/evil"}}}}
	if evalExpr(expr, detections, map[string]string{"Image": "/bin/evil"}) {
		t.Error("not(sel) should be false when sel matches")
	}
	if !evalExpr(expr, detections, map[string]string{"Image": "/bin/ok"}) {
		t.Error("not(sel) should be true when sel does not match")
	}
}

// TestEvaluate_UnsupportedModifierInconclusive guards that a rule using a
// modifier we can't evaluate is reported INCONCLUSIVE, never a silent MISS.
func TestEvaluate_UnsupportedModifierInconclusive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "r.yml")
	rule := "title: t\nlogsource:\n  category: process_creation\ndetection:\n" +
		"  sel:\n    CommandLine|base64|contains: whoami\n  condition: sel\n"
	if err := os.WriteFile(path, []byte(rule), 0644); err != nil {
		t.Fatal(err)
	}
	eval := RuleMatcherEvaluator{RulesDir: dir}
	ev := []model.Event{{Raw: json.RawMessage(`{"Image":"/bin/x","CommandLine":"whoami"}`)}}
	v, _, err := eval.Evaluate(model.SigmaRule{Path: path}, ev)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if v != model.Inconclusive {
		t.Errorf("unsupported-modifier rule → %s, want INCONCLUSIVE", v)
	}
}
