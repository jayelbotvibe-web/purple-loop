package evaluator

import (
	"encoding/json"
	"testing"
)

func TestNormalizer_WindowsSysmon(t *testing.T) {
	raw := json.RawMessage(`{
		"data": {"win": {"eventdata": {
			"image": "C:\\Windows\\SysWOW64\\net.exe",
			"commandLine": "net.exe accounts",
			"parentImage": "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe",
			"user": "NT AUTHORITY\\SYSTEM"
		}}}
	}`)
	n := Normalizer{}
	out := n.Normalize(raw)
	if out["Image"] == "" {
		t.Error("Image empty")
	}
	if out["CommandLine"] == "" {
		t.Error("CommandLine empty")
	}
	if out["ParentImage"] == "" {
		t.Error("ParentImage empty")
	}
	t.Logf("Windows Sysmon: Image=%q CmdLine=%q Parent=%q User=%q",
		out["Image"], out["CommandLine"], out["ParentImage"], out["User"])
}
