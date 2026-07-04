package mapping

import "testing"

func TestLoadCVEMap(t *testing.T) {
	m, err := LoadCVEMap("../../mappings/cve_to_technique.json")
	if err != nil {
		t.Fatalf("LoadCVEMap: %v", err)
	}

	cve := "CVE-2021-44228"
	techniques, atomics, err := m.Resolve(cve)
	if err != nil {
		t.Fatalf("Resolve(%s): %v", cve, err)
	}
	if len(techniques) != 3 {
		t.Errorf("got %d techniques for %s, want 3", len(techniques), cve)
	}
	if ids := atomics["T1059"]; len(ids) == 0 {
		t.Error("no atomics for T1059")
	}

	// Verify unknown CVE returns error
	_, _, err = m.Resolve("CVE-0000-0000")
	if err == nil {
		t.Error("expected error for unknown CVE")
	}

	t.Logf("%s → %v techniques, %d technique→atomics mappings",
		cve, techniques, len(atomics))
}
