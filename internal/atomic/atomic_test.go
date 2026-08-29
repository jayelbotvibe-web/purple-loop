package atomic

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// artRoot is the vendored tree. Tests that need it skip when it is absent so a
// clean checkout without `make atomics` still runs the rest of the suite.
const artRoot = "../../lab/atomic-red-team"

func requireART(t *testing.T) *Registry {
	t.Helper()
	if _, err := os.Stat(filepath.Join(artRoot, "atomics")); err != nil {
		t.Skip("atomic-red-team not vendored; run 'make atomics'")
	}
	reg, err := Load(artRoot, "../../mappings/atomic-overrides.yml")
	if err != nil {
		t.Fatalf("load registry: %v", err)
	}
	return reg
}

func TestParseID(t *testing.T) {
	cases := []struct {
		in    string
		tech  string
		index int
		bad   bool
	}{
		{in: "T1082-3", tech: "T1082", index: 3},
		{in: "T1069.001-1", tech: "T1069.001", index: 1},
		{in: "T1059.004-17", tech: "T1059.004", index: 17},
		{in: "T1082", bad: true},
		{in: "T1082-0", bad: true},
		{in: "1082-1", bad: true},
		{in: "", bad: true},
	}
	for _, c := range cases {
		tech, idx, err := ParseID(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("ParseID(%q) = (%s,%d), want error", c.in, tech, idx)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseID(%q): %v", c.in, err)
			continue
		}
		if tech != c.tech || idx != c.index {
			t.Errorf("ParseID(%q) = (%s,%d), want (%s,%d)", c.in, tech, idx, c.tech, c.index)
		}
	}
}

func TestInterpolateDefaults(t *testing.T) {
	subst := map[string]string{"output_file": "/tmp/x.txt", "host": "127.0.0.1"}
	got := interpolate("uname -a >> #{output_file}; ping #{host}", subst)
	want := "uname -a >> /tmp/x.txt; ping 127.0.0.1"
	if got != want {
		t.Errorf("interpolate = %q, want %q", got, want)
	}
}

// An unknown placeholder must stay visible. Silently emptying it would produce
// a subtly different command than the atomic describes.
func TestInterpolateLeavesUnknownPlaceholder(t *testing.T) {
	got := interpolate("run #{nope}", map[string]string{"other": "x"})
	if got != "run #{nope}" {
		t.Errorf("interpolate = %q, want the placeholder preserved", got)
	}
}

func TestResolveRealAtomic(t *testing.T) {
	reg := requireART(t)
	test, err := reg.Resolve("T1082-3")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if !strings.Contains(test.Command, "uname -a") {
		t.Errorf("T1082-3 command = %q, want it to contain 'uname -a'", test.Command)
	}
	if strings.Contains(test.Command, "#{") {
		t.Errorf("T1082-3 command still has an uninterpolated placeholder: %q", test.Command)
	}
	if !test.SupportsPlatform("linux") || test.SupportsPlatform("windows") {
		t.Errorf("T1082-3 platforms = %v, want linux and not windows", test.SupportedPlatforms)
	}
	if test.Source != SourceART {
		t.Errorf("source = %q, want %q", test.Source, SourceART)
	}
}

// The engine must never invent a command. An unresolvable ID is an error the
// caller has to surface, which is the whole point of this package.
func TestResolveRefusesUnknown(t *testing.T) {
	reg := requireART(t)
	for _, id := range []string{"T9999-1", "T1082-999", "garbage"} {
		if got, err := reg.Resolve(id); err == nil {
			t.Errorf("Resolve(%q) = %+v, want error", id, got)
		}
	}
}

func TestOverrideReplacesCommand(t *testing.T) {
	reg := requireART(t)
	test, err := reg.Resolve("T1518-1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if test.Source != SourceOverride {
		t.Fatalf("T1518-1 source = %q, want %q", test.Source, SourceOverride)
	}
	if test.OverrideReason == "" {
		t.Error("an override must carry a visible reason")
	}
	if !test.SupportsPlatform("linux") {
		t.Error("the T1518 override must declare linux support")
	}
}

// An input-only override keeps the upstream command but pins its inputs.
func TestInputPinningKeepsUpstreamCommand(t *testing.T) {
	reg := requireART(t)
	test, err := reg.Resolve("T1059.004-1")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if test.Source != SourceART {
		t.Errorf("source = %q, want the upstream atomic to be preserved", test.Source)
	}
	if strings.Contains(test.Command, "8.8.8.8") {
		t.Error("containment: the atomic still reaches 8.8.8.8, outside purpleloop-lab")
	}
	if !strings.Contains(test.Command, "127.0.0.1") {
		t.Errorf("pinned host not applied: %q", test.Command)
	}
	if test.OverrideReason == "" {
		t.Error("a pinned input must be reported")
	}
}

func TestOverrideRequiresReason(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ov.yml")
	if err := os.WriteFile(path, []byte("overrides:\n  T1082-1:\n    command: id\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(artRoot, path); err == nil {
		t.Error("an override without a reason must be rejected")
	}
}

// The regression guard for the defect this package exists to fix: every
// technique in the shipped campaign must resolve to its OWN command. If two
// techniques share one, the campaign is testing one behaviour under many names.
func TestCampaignAtomicsAreDistinct(t *testing.T) {
	reg := requireART(t)
	ids := []string{
		"T1059.004-1", "T1087.001-1", "T1082-3", "T1033-2", "T1007-3",
		"T1016-3", "T1049-4", "T1069.001-1", "T1135-1", "T1518-1",
	}
	seen := map[string]string{}
	for _, id := range ids {
		test, err := reg.Resolve(id)
		if err != nil {
			t.Errorf("resolve %s: %v", id, err)
			continue
		}
		if !test.SupportsPlatform("linux") {
			t.Errorf("%s does not support linux (platforms %v) — the Linux campaign cannot run it",
				id, test.SupportedPlatforms)
		}
		if prev, dup := seen[test.Command]; dup {
			t.Errorf("%s and %s resolve to the SAME command — a campaign must not test one behaviour under many names:\n%s",
				prev, id, test.Command)
		}
		seen[test.Command] = id
	}
}
