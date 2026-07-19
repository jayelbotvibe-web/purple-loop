package evaluator

import (
	"encoding/json"
	"testing"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// A command-output log line that merely mentions a binary must NOT count as
// process-creation evidence. Before fidelity gating this produced a false
// DETECTED because the full_log scrape populated CommandLine/Image.
func TestEvaluate_LowFidelityLogDoesNotDetect(t *testing.T) {
	eval := RuleMatcherEvaluator{RulesDir: "../../detections/linux"}
	rule := model.SigmaRule{Path: "../../detections/canary/pipeline_canary.yml"}

	// full_log command output that echoes the canary marker — not a process event.
	raw := json.RawMessage(`{"full_log":"ossec: output: 'echo purpleloop-canary-deadbeef': purpleloop-canary-deadbeef","decoder":{"name":"ossec"}}`)
	events := []model.Event{{ID: "log-1", Raw: raw}}

	verdict, evidence, err := eval.Evaluate(rule, events)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if verdict == model.Detected {
		t.Fatalf("low-fidelity log event must not DETECT a process_creation rule; got %s with %d evidence", verdict, len(evidence))
	}
	if verdict != model.NoTelemetry {
		t.Errorf("expected NO_TELEMETRY when only low-fidelity events exist, got %s", verdict)
	}
}

// Genuine process-creation telemetry (Windows eventdata) must still DETECT.
func TestEvaluate_HighFidelityProcessDetects(t *testing.T) {
	eval := RuleMatcherEvaluator{RulesDir: "../../detections/windows"}
	rule := model.SigmaRule{Path: "../../detections/canary/pipeline_canary.yml"}

	raw := json.RawMessage(`{"data":{"win":{"eventdata":{"commandLine":"cmd.exe /c echo purpleloop-canary-deadbeef","image":"C:\\Windows\\System32\\cmd.exe"}}}}`)
	events := []model.Event{{ID: "win-1", Raw: raw}}

	verdict, evidence, err := eval.Evaluate(rule, events)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if verdict != model.Detected {
		t.Fatalf("high-fidelity process event should DETECT, got %s (%d evidence)", verdict, len(evidence))
	}
}

// The normalizer must tag sources so the evaluator can distinguish them.
func TestNormalizer_FidelityTagging(t *testing.T) {
	n := Normalizer{}
	cases := []struct {
		name string
		raw  string
		want string
	}{
		{"windows eventdata", `{"data":{"win":{"eventdata":{"image":"C:\\a.exe"}}}}`, FidelityProcess},
		{"auditd execve", `{"data":{"audit":{"execve":{"a0":"id"}}}}`, FidelityProcess},
		{"top-level synthetic", `{"Image":"/usr/bin/id","CommandLine":"id"}`, FidelityProcess},
		{"full_log scrape", `{"full_log":"ossec: output: 'id': uid=0"}`, FidelityLog},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := n.Normalize(json.RawMessage(c.raw))
			if out[FidelityKey] != c.want {
				t.Errorf("fidelity = %q, want %q (out=%v)", out[FidelityKey], c.want, out)
			}
		})
	}
}
