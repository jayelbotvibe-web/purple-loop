package evaluator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func TestRuleMatcherEvaluator_DryRun(t *testing.T) {
	e := RuleMatcherEvaluator{RulesDir: "../../detections/linux"}
	raw := json.RawMessage(`{"Image":"/usr/bin/id","ParentImage":"/bin/bash","CommandLine":"id","User":"root"}`)
	events := []model.Event{{ID: "1", Timestamp: time.Now(), Raw: raw}}
	rule := model.SigmaRule{Path: "../../detections/linux/proc_creation_susp_shell.yml"}
	v, ev, err := e.Evaluate(rule, events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	t.Logf("Dry-run: verdict=%s evidence=%d", v, len(ev))
	if v != model.Detected {
		t.Errorf("dry-run should be DETECTED, got %s", v)
	}
}
