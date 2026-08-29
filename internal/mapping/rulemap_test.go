package mapping

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	ruleMapPath   = "../../mappings/attack_rule_map.json"
	detectionsDir = "../../detections"
)

func loadShipped(t *testing.T) *RuleMap {
	t.Helper()
	m, err := LoadRuleMap(ruleMapPath)
	if err != nil {
		t.Fatalf("load rule map: %v", err)
	}
	return m
}

func TestRuleMapEntriesAreComplete(t *testing.T) {
	m := loadShipped(t)
	for id, e := range m.Techniques {
		if len(e.Atomics) == 0 {
			t.Errorf("%s declares no atomic", id)
		}
		if len(e.ExpectedRules) == 0 {
			t.Errorf("%s declares no expected rules", id)
		}
		if e.Platform == "" {
			t.Errorf("%s declares no platform", id)
		}
	}
}

// Every rule a technique expects must exist. A mapping pointing at a deleted
// rule would silently report MISSED forever.
func TestExpectedRulesExistOnDisk(t *testing.T) {
	m := loadShipped(t)
	for id, e := range m.Techniques {
		for _, r := range e.ExpectedRules {
			path := filepath.Join("../..", r)
			if _, err := os.Stat(path); err != nil {
				t.Errorf("%s expects %s, which does not exist", id, r)
			}
		}
	}
}

// The untested-rule lint: every Sigma rule in the repository is either mapped
// to a technique or explicitly declared untested WITH a reason. Without this a
// rule can be added, never exercised, and still be counted as coverage the
// project does not actually have.
func TestEveryRuleIsMappedOrDeclaredUntested(t *testing.T) {
	m := loadShipped(t)
	mapped := m.MappedRules()

	err := filepath.Walk(detectionsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() || !strings.HasSuffix(path, ".yml") {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"tests"+string(filepath.Separator)) {
			return nil // fixtures, not rules
		}
		rel := strings.TrimPrefix(filepath.ToSlash(path), "../../")

		if mapped[rel] {
			return nil
		}
		reason, declared := m.UntestedRules[rel]
		if !declared {
			t.Errorf("rule %s is neither mapped to a technique nor declared in untested_rules — "+
				"an unexercised rule must not be silently counted as coverage", rel)
			return nil
		}
		if strings.TrimSpace(reason) == "" {
			t.Errorf("rule %s is declared untested with no reason", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk detections: %v", err)
	}
}

// The reverse guard: untested_rules must not name a rule that is also mapped,
// or a rule that no longer exists.
func TestUntestedRulesAreConsistent(t *testing.T) {
	m := loadShipped(t)
	mapped := m.MappedRules()
	for rule := range m.UntestedRules {
		if mapped[rule] {
			t.Errorf("%s is listed as untested but is also mapped to a technique", rule)
		}
		if _, err := os.Stat(filepath.Join("../..", rule)); err != nil {
			t.Errorf("%s is listed as untested but does not exist", rule)
		}
	}
}
