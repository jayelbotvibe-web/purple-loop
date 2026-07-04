package evaluator

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func TestPresenceEvaluator_Detected(t *testing.T) {
	e := PresenceEvaluator{}
	events := []model.Event{
		{ID: "1", Timestamp: time.Now(), Raw: json.RawMessage(`{"Image":"/usr/bin/id","ParentImage":"/bin/bash"}`)},
	}
	rule := model.SigmaRule{Path: "proc_creation_susp_shell.yml", Title: "Suspicious shell"}

	verdict, evidence, err := e.Evaluate(rule, events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if verdict != model.Detected {
		t.Errorf("verdict = %s, want DETECTED", verdict)
	}
	if len(evidence) != 1 {
		t.Errorf("evidence len = %d, want 1", len(evidence))
	}
}

func TestPresenceEvaluator_Missed(t *testing.T) {
	e := PresenceEvaluator{}
	rule := model.SigmaRule{Path: "proc_creation_susp_shell.yml", Title: "Suspicious shell"}

	verdict, evidence, err := e.Evaluate(rule, nil)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if verdict != model.Missed {
		t.Errorf("verdict = %s, want MISSED", verdict)
	}
	if evidence != nil {
		t.Errorf("evidence should be nil for MISSED, got %d events", len(evidence))
	}
}

// TestPresenceEvaluator_Fixtures loads positive and negative fixtures;
// the presence evaluator returns DETECTED on both since it only checks
// for any events — real Sigma matching (Phase 2) will differentiate.
func TestPresenceEvaluator_Fixtures(t *testing.T) {
	e := PresenceEvaluator{}
	rule := model.SigmaRule{Path: "proc_creation_susp_shell.yml"}

	// Positive fixture — should be DETECTED
	posEvents := loadFixture(t, "../../detections/tests/proc_creation_susp_shell/positive_events.jsonl")
	verdict, _, err := e.Evaluate(rule, posEvents)
	if err != nil {
		t.Fatalf("positive Evaluate: %v", err)
	}
	if verdict != model.Detected {
		t.Errorf("positive: verdict = %s, want DETECTED", verdict)
	}

	// Negative fixture — presence evaluator still returns DETECTED
	// (real Sigma matching in Phase 2 would return MISSED here)
	negEvents := loadFixture(t, "../../detections/tests/proc_creation_susp_shell/negative_events.jsonl")
	verdict, _, _ = e.Evaluate(rule, negEvents)
	t.Logf("negative fixture verdict (presence): %s (expected MISSED with real Sigma)", verdict)
}

func loadFixture(t *testing.T, path string) []model.Event {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	var events []model.Event
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var raw map[string]any
		if err := json.Unmarshal([]byte(line), &raw); err != nil {
			t.Fatalf("parse fixture line: %v", err)
		}
		events = append(events, model.Event{
			ID:        "fixture",
			Timestamp: time.Now(),
			Raw:       json.RawMessage(line),
		})
	}
	return events
}
