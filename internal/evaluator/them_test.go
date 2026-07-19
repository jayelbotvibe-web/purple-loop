package evaluator

import "testing"

// TestThemExpansion verifies that "1 of them" and "all of them" conditions
// correctly expand to all search-identifiers defined in the rule.
func TestThemExpansion_OneOf(t *testing.T) {
	// Rule: two selections, condition: 1 of them
	// Means: at least one of {sel_a, sel_b} matches
	rule := &Rule{
		Detections: map[string]FieldMap{
			"sel_a": {"Image": FieldEntry{Values: []string{"cmd.exe"}}},
			"sel_b": {"CommandLine": FieldEntry{Values: []string{"whoami"}}},
		},
		Condition: OneOfExpr{N: 1, Names: []string{}}, // "1 of them" → empty Names
	}

	m := Matcher{}

	// Event matching sel_a (cmd.exe) but NOT sel_b
	evA := map[string]string{"Image": "cmd.exe", "CommandLine": "nope"}
	if !m.Match(rule, evA) {
		t.Error("1 of them: event matching sel_a should match (at least 1 of 2)")
	}

	// Event matching sel_b (whoami) but NOT sel_a
	evB := map[string]string{"Image": "nope", "CommandLine": "whoami"}
	if !m.Match(rule, evB) {
		t.Error("1 of them: event matching sel_b should match (at least 1 of 2)")
	}

	// Event matching neither
	evC := map[string]string{"Image": "nope", "CommandLine": "nope"}
	if m.Match(rule, evC) {
		t.Error("1 of them: event matching neither should NOT match")
	}
}

func TestThemExpansion_AllOf(t *testing.T) {
	// Rule: two selections, condition: all of them
	// Means: both {sel_a, sel_b} must match
	rule := &Rule{
		Detections: map[string]FieldMap{
			"sel_a": {"Image": FieldEntry{Values: []string{"cmd.exe"}}},
			"sel_b": {"CommandLine": FieldEntry{Values: []string{"whoami"}}},
		},
		Condition: AllOfExpr{Names: []string{}}, // "all of them" → empty Names
	}

	m := Matcher{}

	// Event matching both
	evBoth := map[string]string{"Image": "cmd.exe", "CommandLine": "whoami"}
	if !m.Match(rule, evBoth) {
		t.Error("all of them: event matching both should match")
	}

	// Event matching only sel_a
	evA := map[string]string{"Image": "cmd.exe", "CommandLine": "nope"}
	if m.Match(rule, evA) {
		t.Error("all of them: event matching only sel_a should NOT match")
	}

	// Event matching only sel_b
	evB := map[string]string{"Image": "nope", "CommandLine": "whoami"}
	if m.Match(rule, evB) {
		t.Error("all of them: event matching only sel_b should NOT match")
	}
}
