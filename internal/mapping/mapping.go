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
