// Package mapping resolves CVEs to techniques and atomic test IDs.
package mapping

import (
	"encoding/json"
	"fmt"
	"os"
)

// CVEEntry maps a single CVE to its techniques and atomics.
type CVEEntry struct {
	Description string              `json:"description"`
	Techniques  []string            `json:"techniques"`
	Atomics     map[string][]string `json:"atomics"`
}

// CVEMap is the top-level mapping file.
type CVEMap map[string]CVEEntry

// LoadCVEMap reads a CVE-to-technique mapping file.
func LoadCVEMap(path string) (CVEMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CVE map: %w", err)
	}
	var m CVEMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse CVE map: %w", err)
	}
	return m, nil
}

// Resolve returns the techniques and atomic IDs for a given CVE.
func (m CVEMap) Resolve(cve string) (techniques []string, techniqueAtomics map[string][]string, err error) {
	entry, ok := m[cve]
	if !ok {
		return nil, nil, fmt.Errorf("CVE %s not in mapping", cve)
	}
	return entry.Techniques, entry.Atomics, nil
}

// ---- technique -> atomic -> expected detections ----

// TechniqueEntry declares which atomic exercises a technique and which Sigma
// rules are expected to fire for it. expected_rules is a list, not one path:
// a technique may legitimately be caught by any of several rules, and asserting
// a single one understates coverage.
type TechniqueEntry struct {
	Atomics       []string `json:"atomics"`
	Platform      string   `json:"platform"`
	ExpectedRules []string `json:"expected_rules"`
}

// RuleMap is the single source of truth for what a campaign should run and what
// should catch it. It replaces the technique->rule map that was hardcoded in
// cmd/purpleloop, so the mapping is data the repository can lint rather than
// code nobody can inspect.
type RuleMap struct {
	Techniques    map[string]TechniqueEntry `json:"techniques"`
	UntestedRules map[string]string         `json:"untested_rules"`
}

// LoadRuleMap reads the technique/rule mapping file.
func LoadRuleMap(path string) (*RuleMap, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read rule map: %w", err)
	}
	var m RuleMap
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse rule map %s: %w", path, err)
	}
	if len(m.Techniques) == 0 {
		return nil, fmt.Errorf("rule map %s declares no techniques", path)
	}
	return &m, nil
}

// Entry returns the mapping for a technique.
func (m *RuleMap) Entry(technique string) (TechniqueEntry, bool) {
	e, ok := m.Techniques[technique]
	return e, ok
}

// ExpectedRules returns the rules that should fire for a technique.
func (m *RuleMap) ExpectedRules(technique string) []string {
	if e, ok := m.Techniques[technique]; ok {
		return e.ExpectedRules
	}
	return nil
}

// AtomicFor returns the mapped atomic ID for a technique, if one is declared.
func (m *RuleMap) AtomicFor(technique string) string {
	if e, ok := m.Techniques[technique]; ok && len(e.Atomics) > 0 {
		return e.Atomics[0]
	}
	return ""
}

// MappedRules returns every rule path referenced by any technique, so a lint
// can tell which rules on disk are never exercised.
func (m *RuleMap) MappedRules() map[string]bool {
	out := map[string]bool{}
	for _, e := range m.Techniques {
		for _, r := range e.ExpectedRules {
			out[r] = true
		}
	}
	return out
}
