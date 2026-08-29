package precision

import (
	"testing"

	"github.com/jayelbotvibe-web/purple-loop/internal/evaluator"
)

const (
	baselinePath = "../../emulation/benign-baseline.yml"
	rulesDir     = "../../detections/linux"
)

// The precision gate. Every shipped rule must stay silent during ordinary
// administration, including the adjacent cases — benign uses of the very
// binaries the detections watch. A rule keyed on a tool name rather than on
// what the tool is being asked to do fires here and fails the build.
//
// This found two real false positives when it was introduced: T1087.001 fired
// on `getent hosts` (a DNS lookup, not account enumeration) and T1135 fired on
// a bare `mount`. Both rules were narrowed.
func TestRulesAreSilentOnBenignWorkload(t *testing.T) {
	b, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("load baseline: %v", err)
	}
	res, err := Measure(evaluator.RuleMatcherEvaluator{RulesDir: rulesDir}, rulesDir, b)
	if err != nil {
		t.Fatalf("measure: %v", err)
	}
	for _, fp := range res.FalsePositives {
		t.Errorf("false positive: %s fired on benign %q (%s)", fp.Rule, fp.Command, fp.Category)
	}
	if res.PrecisionPct != 100 {
		t.Errorf("precision = %d%%, want 100%% (%d commands, %d rules)",
			res.PrecisionPct, res.CommandsRun, res.RulesChecked)
	}
}

// A baseline with no adjacent cases proves nothing — it would pass against a
// rule set that matches only exact strings. Guard the guard.
func TestBaselineIncludesAdjacentCases(t *testing.T) {
	b, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	adjacent := 0
	for _, c := range b.Commands {
		if c.Category == "adjacent-benign" {
			adjacent++
		}
	}
	if adjacent < 5 {
		t.Errorf("baseline has %d adjacent-benign commands, want at least 5 — "+
			"without benign uses of the watched binaries this test is vacuous", adjacent)
	}
	if len(b.Commands) < 20 {
		t.Errorf("baseline has %d commands, want at least 20", len(b.Commands))
	}
}

func TestLoadBaselineRejectsIncomplete(t *testing.T) {
	if _, err := LoadBaseline("does-not-exist.yml"); err == nil {
		t.Error("a missing baseline must error")
	}
}
