package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestProofChainMarshal(t *testing.T) {
	now := time.Date(2026, 7, 4, 9, 12, 3, 0, time.UTC)
	chain := ProofChain{
		TechniqueID:     "T1059.004",
		SourceCVE:       "CVE-2025-XXXXX",
		ArbiterPriority: 0.91,
		Atomic: AtomicTest{
			ID:          "T1059.004-1",
			TechniqueID: "T1059.004",
			Command:     "sh -c 'id; whoami'",
			Executor:    "bash",
		},
		ExecutedAt:      now,
		EventsCollected: 3,
		RuleMatched:     "detections/linux/proc_creation_susp_shell.yml",
		Verdict:         Detected,
		Evidence: []Event{
			{ID: "evt-1", Timestamp: now, Raw: json.RawMessage(`{"key":"val"}`)},
		},
	}

	b, err := json.MarshalIndent(chain, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Verify every key from DESIGN.md §4 is present
	required := []string{
		`"technique_id"`, `"source_cve"`, `"arbiter_priority"`,
		`"atomic"`, `"executed_at"`, `"events_collected"`,
		`"rule_matched"`, `"verdict"`, `"evidence"`,
	}
	s := string(b)
	for _, k := range required {
		if !strings.Contains(s, k) {
			t.Errorf("missing key %s in:\n%s", k, s)
		}
	}

	// Verify verdict value
	if !strings.Contains(s, `"verdict": "DETECTED"`) {
		t.Errorf("verdict not DETECTED in:\n%s", s)
	}

	// Round-trip: unmarshal back
	var back ProofChain
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.TechniqueID != "T1059.004" || back.Verdict != Detected {
		t.Errorf("round-trip mismatch: %+v", back)
	}
}
