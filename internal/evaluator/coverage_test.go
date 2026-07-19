package evaluator

import (
	"os"
	"testing"
)

// mustParse parses a Sigma rule from an in-memory YAML string via a temp file,
// exercising the real parser path.
func mustParse(t *testing.T, yaml string) *Rule {
	t.Helper()
	path := t.TempDir() + "/rule.yml"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("write rule: %v", err)
	}
	r, err := RuleParser{}.Parse(path)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r
}

func TestMatcher_Regex(t *testing.T) {
	rule := mustParse(t, `
title: regex
logsource:
  category: process_creation
detection:
  selection:
    CommandLine|re: 'nc\s+-l\s+\d+'
  condition: selection
`)
	m := Matcher{}
	if !m.Match(rule, map[string]string{"CommandLine": "nc -l 4444"}) {
		t.Error("regex should match 'nc -l 4444'")
	}
	if m.Match(rule, map[string]string{"CommandLine": "netcat listening"}) {
		t.Error("regex should not match 'netcat listening'")
	}
}

func TestMatcher_Numeric(t *testing.T) {
	rule := mustParse(t, `
title: numeric
detection:
  selection:
    EventID: 4688
    Count|gt: 5
  condition: selection
`)
	m := Matcher{}
	if !m.Match(rule, map[string]string{"EventID": "4688", "Count": "9"}) {
		t.Error("Count 9 > 5 should match")
	}
	if m.Match(rule, map[string]string{"EventID": "4688", "Count": "3"}) {
		t.Error("Count 3 > 5 should not match")
	}
}

func TestMatcher_Keywords(t *testing.T) {
	rule := mustParse(t, `
title: keywords
detection:
  keywords:
    - 'mimikatz'
    - 'sekurlsa'
  condition: keywords
`)
	m := Matcher{}
	if !m.Match(rule, map[string]string{"CommandLine": "invoke-mimikatz -dumpcreds"}) {
		t.Error("keyword 'mimikatz' should match in CommandLine")
	}
	if m.Match(rule, map[string]string{"CommandLine": "whoami /all"}) {
		t.Error("no keyword present should not match")
	}
}
