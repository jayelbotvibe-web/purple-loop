package evaluator

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func TestWindowsEndToEnd(t *testing.T) {
	// Captured Windows Sysmon Event ID 1 (net.exe)
	raw := json.RawMessage(`{
		"data": {"win": {"eventdata": {
			"image": "C:\\Windows\\SysWOW64\\net.exe",
			"commandLine": "net.exe accounts",
			"parentImage": "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe",
			"user": "NT AUTHORITY\\SYSTEM"
		}}}
	}`)
	events := []model.Event{{ID: "win-1", Timestamp: time.Now(), Raw: raw}}
	rule := model.SigmaRule{Path: "../../detections/windows/win_proc_create.yml"}
	e := RuleMatcherEvaluator{RulesDir: "../../detections/windows"}

	v, ev, err := e.Evaluate(rule, events)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if v != model.Detected {
		t.Errorf("Windows Sysmon event should be DETECTED, got %s", v)
	}
	t.Logf("Windows: verdict=%s evidence=%d", v, len(ev))
}
