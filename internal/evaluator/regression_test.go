package evaluator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigmaMatcher_ProcCreationSuspShell(t *testing.T) {
	parser := RuleParser{}
	rule, err := parser.Parse("../../detections/linux/proc_creation_susp_shell.yml")
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}

	matcher := Matcher{}

	// Test positive fixtures — all must match
	posEvents := loadJSONLEvents(t, "../../detections/tests/proc_creation_susp_shell/positive_events.jsonl")
	for i, ev := range posEvents {
		if !matcher.Match(rule, ev) {
			t.Errorf("positive[%d] should match: %v", i, ev)
		}
	}

	// Test negative fixtures — none must match
	negEvents := loadJSONLEvents(t, "../../detections/tests/proc_creation_susp_shell/negative_events.jsonl")
	for i, ev := range negEvents {
		if matcher.Match(rule, ev) {
			t.Errorf("negative[%d] should NOT match: %v", i, ev)
		}
	}

	t.Logf("rule %q: %d positive matches, %d negative rejections OK",
		rule.Title, len(posEvents), len(negEvents))
}

// regressAllRules tests every rule with a fixture directory.
func TestRegression_AllRules(t *testing.T) {
	parser := RuleParser{}
	matcher := Matcher{}

	rulesDir := "../../detections/linux"
	testsDir := "../../detections/tests"

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		t.Fatalf("read rules dir: %v", err)
	}

	tested := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		ruleName := strings.TrimSuffix(e.Name(), ".yml")
		fixtureDir := filepath.Join(testsDir, ruleName)
		if _, err := os.Stat(fixtureDir); os.IsNotExist(err) {
			continue
		}

		rulePath := filepath.Join(rulesDir, e.Name())
		rule, err := parser.Parse(rulePath)
		if err != nil {
			t.Errorf("parse %s: %v", ruleName, err)
			continue
		}

		posFile := filepath.Join(fixtureDir, "positive_events.jsonl")
		negFile := filepath.Join(fixtureDir, "negative_events.jsonl")

		// Positives must match
		posEvents := loadJSONLEvents(t, posFile)
		for i, ev := range posEvents {
			if !matcher.Match(rule, ev) {
				t.Errorf("%s: positive[%d] should match: %v", ruleName, i, ev)
			}
		}

		// Negatives must NOT match
		negEvents := loadJSONLEvents(t, negFile)
		for i, ev := range negEvents {
			if matcher.Match(rule, ev) {
				t.Errorf("%s: negative[%d] should NOT match: %v", ruleName, i, ev)
			}
		}

		tested++
	}

	if tested == 0 {
		t.Fatal("no rules with fixture directories found")
	}
	t.Logf("Regression: %d rules tested, all positive/negative fixtures correct", tested)
}

func loadJSONLEvents(t *testing.T, path string) []map[string]string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var events []map[string]string
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("parse fixture line in %s: %v", path, err)
		}
		ev := make(map[string]string)
		for k, v := range raw {
			if s, ok := v.(string); ok {
				ev[k] = s
			}
		}
		events = append(events, ev)
	}
	return events
}
