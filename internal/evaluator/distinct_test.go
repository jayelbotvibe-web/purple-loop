package evaluator

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Nine of the ten Linux rules were once byte-identical in logic — every one
// matched `Image endswith /id or /whoami`, differing only in title — because
// they were written against an engine that executed `id; whoami` for every
// technique. The CI regression suite passed the whole time, since all nine
// shared one positive fixture too.
//
// A campaign whose detections are one rule under many names reports coverage it
// does not have. This test makes that unshippable.
func TestRulesHaveDistinctLogic(t *testing.T) {
	dirs := []string{"../../detections/linux", "../../detections/windows"}
	byLogic := map[string][]string{}

	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read %s: %v", path, err)
			}
			var doc struct {
				Detection map[string]any `yaml:"detection"`
			}
			if err := yaml.Unmarshal(data, &doc); err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			if len(doc.Detection) == 0 {
				t.Errorf("%s has no detection block", path)
				continue
			}
			// Canonicalise so formatting differences do not mask identical logic.
			canon, err := json.Marshal(normalize(doc.Detection))
			if err != nil {
				t.Fatal(err)
			}
			sum := sha256.Sum256(canon)
			key := hex.EncodeToString(sum[:8])
			byLogic[key] = append(byLogic[key], filepath.Join(filepath.Base(dir), e.Name()))
		}
	}

	for _, rules := range byLogic {
		if len(rules) > 1 {
			t.Errorf("these rules have IDENTICAL detection logic: %s\n"+
				"each technique needs a detection for what its own atomic does — "+
				"duplicate logic reports coverage the campaign does not have",
				strings.Join(rules, ", "))
		}
	}
}

// normalize converts a YAML tree into a form with deterministic ordering, so
// two logically identical detections hash the same.
func normalize(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = normalize(val)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[strings.TrimSpace(toString(k))] = normalize(val)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = normalize(val)
		}
		return out
	default:
		return v
	}
}

func toString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// Every rule mapped to a technique must actually reference that technique in
// its tags, so a mapping cannot quietly point at an unrelated detection.
func TestRuleTagsMatchTechnique(t *testing.T) {
	entries, err := os.ReadDir("../../detections/linux")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".yml") {
			continue
		}
		tech := strings.TrimSuffix(name, ".yml")
		if !strings.HasPrefix(tech, "T1") {
			continue // rules named by behaviour rather than technique
		}
		data, err := os.ReadFile(filepath.Join("../../detections/linux", name))
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Tags []string `yaml:"tags"`
		}
		if err := yaml.Unmarshal(data, &doc); err != nil {
			t.Fatal(err)
		}
		want := "attack." + strings.ToLower(tech)
		found := false
		for _, tag := range doc.Tags {
			if strings.EqualFold(strings.TrimSpace(tag), want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s does not tag %s (tags: %v)", name, want, doc.Tags)
		}
	}
}
