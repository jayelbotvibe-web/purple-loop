package main

import (
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/mapping"
	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func win(startSec, endSec int) model.TimeWindow {
	base := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	return model.TimeWindow{
		Start: base.Add(time.Duration(startSec) * time.Second),
		End:   base.Add(time.Duration(endSec) * time.Second),
	}
}

func TestLabelAttributionSyntheticIsUnscoped(t *testing.T) {
	chains := []model.ProofChain{{Window: win(0, 10)}}
	labelAttribution(chains, true, "victim01")
	if chains[0].Attribution != model.Unscoped {
		t.Errorf("synthetic run = %q, want %q", chains[0].Attribution, model.Unscoped)
	}
}

func TestLabelAttributionDetectsOverlap(t *testing.T) {
	chains := []model.ProofChain{
		{TechniqueID: "T1082", Window: win(0, 60)},
		{TechniqueID: "T1033", Window: win(30, 90)}, // overlaps the first
		{TechniqueID: "T1007", Window: win(200, 260)},
	}
	labelAttribution(chains, false, "victim01")

	if chains[0].Attribution != model.WindowOverlap {
		t.Errorf("T1082 = %q, want %q", chains[0].Attribution, model.WindowOverlap)
	}
	if chains[1].Attribution != model.WindowOverlap {
		t.Errorf("T1033 = %q, want %q", chains[1].Attribution, model.WindowOverlap)
	}
	if chains[2].Attribution != model.WindowAndHostScoped {
		t.Errorf("T1007 = %q, want %q", chains[2].Attribution, model.WindowAndHostScoped)
	}
}

func TestLabelAttributionWithoutHost(t *testing.T) {
	chains := []model.ProofChain{{Window: win(0, 10)}}
	labelAttribution(chains, false, "")
	if chains[0].Attribution != model.WindowScoped {
		t.Errorf("no host = %q, want %q", chains[0].Attribution, model.WindowScoped)
	}
}

// A technique that never ran has no window, so nothing can be attributed to it.
func TestLabelAttributionNoWindow(t *testing.T) {
	chains := []model.ProofChain{{TechniqueID: "T1518", Verdict: model.SkippedPrereq}}
	labelAttribution(chains, false, "victim01")
	if chains[0].Attribution != model.Unscoped {
		t.Errorf("unrun technique = %q, want %q", chains[0].Attribution, model.Unscoped)
	}
}

// stubEval returns a canned verdict per rule path.
type stubEval map[string]model.Verdict

func (s stubEval) Evaluate(rule model.SigmaRule, events []model.Event) (model.Verdict, []model.Event, error) {
	v, ok := s[rule.Path]
	if !ok {
		v = model.Missed
	}
	if v == model.Detected {
		return v, []model.Event{{ID: "ev-" + rule.Path}}, nil
	}
	return v, nil, nil
}

// The point of expected_rules: a second rule catching the behaviour is still a
// detection. Evaluating only the first would report a gap that does not exist.
func TestEvaluateExpectedAnyRuleDetects(t *testing.T) {
	eval := stubEval{"a.yml": model.Missed, "b.yml": model.Detected}
	v, ev, matched, err := evaluateExpected(eval, []string{"a.yml", "b.yml"}, "T1082", []model.Event{{}})
	if err != nil {
		t.Fatal(err)
	}
	if v != model.Detected {
		t.Errorf("verdict = %q, want DETECTED", v)
	}
	if len(matched) != 1 || matched[0] != "b.yml" {
		t.Errorf("matched = %v, want [b.yml]", matched)
	}
	if len(ev) == 0 {
		t.Error("a detection must carry its evidence")
	}
}

// NO_TELEMETRY only stands when no rule saw usable events. A real MISSED from
// any rule outranks it, because something was actually evaluated.
func TestEvaluateExpectedVerdictPrecedence(t *testing.T) {
	cases := []struct {
		name string
		eval stubEval
		want model.Verdict
	}{
		{"missed beats no_telemetry", stubEval{"a.yml": model.NoTelemetry, "b.yml": model.Missed}, model.Missed},
		{"inconclusive beats no_telemetry", stubEval{"a.yml": model.NoTelemetry, "b.yml": model.Inconclusive}, model.Inconclusive},
		{"detected beats all", stubEval{"a.yml": model.Missed, "b.yml": model.Detected}, model.Detected},
		{"all silent stays no_telemetry", stubEval{"a.yml": model.NoTelemetry, "b.yml": model.NoTelemetry}, model.NoTelemetry},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v, _, _, err := evaluateExpected(c.eval, []string{"a.yml", "b.yml"}, "T", []model.Event{{}})
			if err != nil {
				t.Fatal(err)
			}
			if v != c.want {
				t.Errorf("verdict = %q, want %q", v, c.want)
			}
		})
	}
}

func TestDetectLatency(t *testing.T) {
	start := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	ev := []model.Event{
		{Timestamp: start.Add(5 * time.Second)},
		{Timestamp: start.Add(2 * time.Second)}, // earliest wins
	}
	if got := detectLatency(start, ev); got != 2000 {
		t.Errorf("latency = %dms, want 2000", got)
	}
	// An event stamped before the execution cannot be its evidence.
	if got := detectLatency(start, []model.Event{{Timestamp: start.Add(-time.Second)}}); got != 0 {
		t.Errorf("pre-execution event gave latency %d, want 0", got)
	}
	if got := detectLatency(start, nil); got != 0 {
		t.Errorf("no evidence gave latency %d, want 0", got)
	}
}

// Replaying the shipped dataset runs the REAL evaluator over real event shapes,
// with no lab, no Docker and no Wazuh. This is the regression test the project
// could not previously have: rule edits are now checked against telemetry
// rather than only against fixtures written to match them.
//
// The expected verdicts are deliberately mixed. A sample where everything
// passes would not catch a rule that matches everything.
func TestReplaySampleDataset(t *testing.T) {
	result, err := replayDataset("../../testdata/sample-run",
		"../../mappings/attack_rule_map.json", "../../detections/linux")
	if err != nil {
		t.Fatalf("replay: %v", err)
	}

	want := map[string]model.Verdict{
		"T1082": model.Detected,
		"T1033": model.Detected,
		"T1049": model.Detected,
		"T1518": model.Missed, // ran, produced telemetry, rule legitimately did not match
	}
	if len(result.Chains) != len(want) {
		t.Fatalf("chains = %d, want %d", len(result.Chains), len(want))
	}
	for _, c := range result.Chains {
		w, ok := want[c.TechniqueID]
		if !ok {
			t.Errorf("unexpected technique %s in replay", c.TechniqueID)
			continue
		}
		if c.Verdict != w {
			t.Errorf("%s = %s, want %s (note: %s)", c.TechniqueID, c.Verdict, w, c.Note)
		}
		if c.EventsCollected == 0 {
			t.Errorf("%s replayed with no events", c.TechniqueID)
		}
	}
}

// A replay is a real evaluation of real telemetry, so it must never be marked
// synthetic — that flag means "fabricated", and mislabelling would either
// suppress a valid result or launder a fake one.
func TestReplayIsNotSynthetic(t *testing.T) {
	result, err := replayDataset("../../testdata/sample-run",
		"../../mappings/attack_rule_map.json", "../../detections/linux")
	if err != nil {
		t.Fatal(err)
	}
	if result.Synthetic {
		t.Error("a replay of captured telemetry is not a synthetic run")
	}
}

func TestCompareRunsClassifiesChanges(t *testing.T) {
	before := map[string]string{
		"T1082": "DETECTED",
		"T1033": "MISSED",
		"T1049": "DETECTED",
		"T1007": "NO_TELEMETRY",
		"T1016": "DETECTED",
	}
	after := map[string]string{
		"T1082": "MISSED",   // regression — the one that matters
		"T1033": "DETECTED", // improvement
		"T1049": "DETECTED", // unchanged
		"T1007": "ERROR",    // regression: it used to at least collect
		"T1518": "DETECTED", // newly present
		// T1016 absent
	}

	reg, imp, other := compareRuns(before, after)

	if len(reg) != 2 {
		t.Errorf("regressions = %v, want 2 — T1082 and T1007; T1016 dropping out is a change, not a regression", reg)
	}
	found := map[string]string{}
	for _, c := range reg {
		found[c.Technique] = c.From + "->" + c.To
	}
	if found["T1082"] != "DETECTED->MISSED" {
		t.Errorf("T1082 = %q, want DETECTED->MISSED", found["T1082"])
	}
	if found["T1007"] != "NO_TELEMETRY->ERROR" {
		t.Errorf("T1007 = %q, want NO_TELEMETRY->ERROR", found["T1007"])
	}

	if len(imp) != 1 || imp[0].Technique != "T1033" {
		t.Errorf("improvements = %v, want just T1033", imp)
	}

	// Techniques appearing or disappearing are changes, but not regressions.
	otherSet := map[string]bool{}
	for _, c := range other {
		otherSet[c.Technique] = true
	}
	if !otherSet["T1518"] || !otherSet["T1016"] {
		t.Errorf("other = %v, want T1518 (new) and T1016 (absent)", other)
	}
}

// Verdicts that all mean "never exercised" must not read as regressions of one
// another — moving from ERROR to SKIPPED_PREREQ is a different explanation of
// the same non-result, not a detection getting worse.
func TestCompareRunsNotExercisedVerdictsAreEqualRank(t *testing.T) {
	reg, imp, other := compareRuns(
		map[string]string{"T1": "ERROR"},
		map[string]string{"T1": "SKIPPED_PREREQ"})
	if len(reg) != 0 || len(imp) != 0 {
		t.Errorf("want no regression/improvement, got reg=%v imp=%v", reg, imp)
	}
	if len(other) != 1 {
		t.Errorf("want the change reported as 'other', got %v", other)
	}
}

func TestCompareRunsIdenticalIsQuiet(t *testing.T) {
	m := map[string]string{"T1082": "DETECTED", "T1033": "MISSED"}
	reg, imp, other := compareRuns(m, m)
	if len(reg)+len(imp)+len(other) != 0 {
		t.Errorf("identical runs must produce no changes: %v %v %v", reg, imp, other)
	}
}

// `--technique T1082` must use the atomic the rule map names (T1082-3, Linux),
// not ART's first test (T1082-1, Windows). Guessing "<technique>-1" picks the
// Windows atomic for most techniques, which then errors on the Linux victim.
func TestAtomicIDForPrefersRuleMapOverGuess(t *testing.T) {
	rules, err := mapping.LoadRuleMap("../../mappings/attack_rule_map.json")
	if err != nil {
		t.Fatal(err)
	}
	task := model.TechniqueTask{TechniqueID: "T1082"} // no atomic named
	if got := atomicIDFor(task, rules); got != "T1082-3" {
		t.Errorf("atomicIDFor = %q, want T1082-3 from the rule map", got)
	}

	// An explicit plan choice still wins over the map.
	task.AtomicIDs = []string{"T1082-8"}
	if got := atomicIDFor(task, rules); got != "T1082-8" {
		t.Errorf("atomicIDFor = %q, want the plan's explicit T1082-8", got)
	}

	// Only with neither does it fall back to the guess.
	unmapped := model.TechniqueTask{TechniqueID: "T9999"}
	if got := atomicIDFor(unmapped, rules); got != "T9999-1" {
		t.Errorf("atomicIDFor = %q, want the T9999-1 fallback", got)
	}
}
