package evaluator

import (
	"encoding/json"
	"testing"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func normalizeRaw(t *testing.T, raw string) map[string]string {
	t.Helper()
	return Normalizer{}.Normalize(json.RawMessage(raw))
}

// Sysmon for Linux EventID 1 is genuine process creation and must satisfy a
// process_creation rule.
func TestLinuxSysmonProcessCreateIsHighFidelity(t *testing.T) {
	got := normalizeRaw(t, `{"data":{"sysmon":{
		"eventID":"1","image":"/usr/bin/uname","commandLine":"uname -a",
		"parentImage":"/bin/bash","user":"root"}}}`)

	if got["Image"] != "/usr/bin/uname" {
		t.Errorf("Image = %q", got["Image"])
	}
	if got["CommandLine"] != "uname -a" {
		t.Errorf("CommandLine = %q", got["CommandLine"])
	}
	if got["ParentImage"] != "/bin/bash" {
		t.Errorf("ParentImage = %q", got["ParentImage"])
	}
	if got[FidelityKey] != FidelityProcess {
		t.Errorf("fidelity = %q, want %q", got[FidelityKey], FidelityProcess)
	}
}

// The eventID may arrive as a JSON number rather than a string.
func TestLinuxSysmonNumericEventID(t *testing.T) {
	got := normalizeRaw(t, `{"data":{"sysmon":{
		"eventID":1,"image":"/usr/bin/id","commandLine":"id"}}}`)
	if got[FidelityKey] != FidelityProcess {
		t.Errorf("numeric eventID not recognised: fidelity = %q", got[FidelityKey])
	}
	if got["EventID"] != "1" {
		t.Errorf("EventID = %q, want \"1\"", got["EventID"])
	}
}

// A non-creation Sysmon event carries a process name without being proof a
// process was created — the same trap that produced a false DETECTED off a
// Windows 4798 enumeration event.
func TestLinuxSysmonNonCreationIsLowFidelity(t *testing.T) {
	got := normalizeRaw(t, `{"data":{"sysmon":{
		"eventID":"3","image":"/usr/bin/curl","commandLine":"curl http://x"}}}`)

	if got[FidelityKey] == FidelityProcess {
		t.Error("a Sysmon network event must not be tagged as process creation")
	}
	if got[FidelityKey] != FidelityLog {
		t.Errorf("fidelity = %q, want %q", got[FidelityKey], FidelityLog)
	}
}

// End to end: a Linux-Sysmon event must be able to satisfy a real shipped rule,
// and a non-creation event with the same fields must not.
func TestLinuxSysmonSatisfiesShippedRule(t *testing.T) {
	e := RuleMatcherEvaluator{RulesDir: "../../detections/linux"}
	rule := model.SigmaRule{Path: "../../detections/linux/T1082.yml", Title: "T1082"}

	creation := []model.Event{{Raw: json.RawMessage(`{"data":{"sysmon":{
		"eventID":"1","image":"/usr/bin/uname","commandLine":"uname -a","user":"root"}}}`)}}
	verdict, evidence, err := e.Evaluate(rule, creation)
	if err != nil {
		t.Fatal(err)
	}
	if verdict != model.Detected {
		t.Errorf("verdict = %s, want DETECTED", verdict)
	}
	if len(evidence) == 0 {
		t.Error("a detection must carry evidence")
	}

	nonCreation := []model.Event{{Raw: json.RawMessage(`{"data":{"sysmon":{
		"eventID":"3","image":"/usr/bin/uname","commandLine":"uname -a","user":"root"}}}`)}}
	verdict, _, err = e.Evaluate(rule, nonCreation)
	if err != nil {
		t.Fatal(err)
	}
	if verdict == model.Detected {
		t.Error("a non-creation event must never satisfy a process_creation rule")
	}
}
