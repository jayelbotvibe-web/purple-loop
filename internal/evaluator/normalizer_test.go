package evaluator

import (
	"encoding/json"
	"testing"
)

func TestNormalizer_Windows(t *testing.T) {
	// Real captured Windows Security Audit event (agent 002)
	raw := json.RawMessage(`{
		"data": {
			"win": {
				"eventdata": {
					"callerProcessName": "C:\\Windows\\SysWOW64\\net1.exe",
					"subjectUserName": "DESKTOP-MONE3R9$"
				}
			}
		},
		"full_log": "{\"win\":{\"system\":{\"eventID\":\"4798\"}}}"
	}`)

	n := Normalizer{}
	out := n.Normalize(raw)

	if out["Image"] == "" {
		t.Error("Windows: Image should not be empty")
	}
	if out["User"] == "" {
		t.Error("Windows: User should not be empty")
	}
	t.Logf("Windows → Image=%q User=%q", out["Image"], out["User"])
}

func TestNormalizer_Linux(t *testing.T) {
	// Real captured Linux command output event (agent 001)
	raw := json.RawMessage(`{
		"full_log": "ossec: output: 'df -P': /dev/nvme0n1p2 490048472 192860636 272221232 42% /etc/hosts",
		"decoder": {"name": "ossec"}
	}`)

	n := Normalizer{}
	out := n.Normalize(raw)

	if out["Image"] == "" {
		t.Error("Linux: Image should not be empty")
	}
	t.Logf("Linux → Image=%q", out["Image"])
}

func TestNormalizer_DryRun(t *testing.T) {
	// Dry-run synthetic event must normalize for --dry-run support
	raw := json.RawMessage(`{"agent":"victim01","note":"dry-run event","rule":"synthetic"}`)
	n := Normalizer{}
	out := n.Normalize(raw)
	// Dry events have no canonical fields — that's fine for testing
	t.Logf("Dry-run → %v", out)
}
