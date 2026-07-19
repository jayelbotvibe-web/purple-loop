package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func sampleRun() model.CampaignResult {
	return model.CampaignResult{
		StartedAt: time.Date(2026, 7, 4, 9, 0, 0, 0, time.UTC),
		Chains: []model.ProofChain{
			{TechniqueID: "T1059.004", SourceCVE: "CVE-2026-0001", ArbiterPriority: 0.91,
				Verdict: model.Detected, EventsCollected: 3, RuleMatched: "win_proc_create.yml"},
			{TechniqueID: "T1082", Verdict: model.NoTelemetry, EventsCollected: 0},
			{TechniqueID: "T1016", Verdict: model.Missed, EventsCollected: 5},
		},
	}
}

func TestJSONReporter(t *testing.T) {
	var buf bytes.Buffer
	if err := (JSONReporter{Out: &buf}).Write(sampleRun()); err != nil {
		t.Fatalf("write: %v", err)
	}
	var back model.CampaignResult
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(back.Chains) != 3 || back.Chains[0].TechniqueID != "T1059.004" {
		t.Errorf("round-trip mismatch: %+v", back.Chains)
	}
}

func TestHTMLReporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.html")
	if err := (HTMLReporter{Path: path}).Write(sampleRun()); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, _ := os.ReadFile(path)
	html := string(data)
	for _, want := range []string{"T1059.004", "DETECTED", "NO_TELEMETRY", "<table"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML report missing %q", want)
		}
	}
}

func TestNavigatorLayerReporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "layer.json")
	if err := (NavigatorLayerReporter{Path: path}).Write(sampleRun()); err != nil {
		t.Fatalf("write: %v", err)
	}
	data, _ := os.ReadFile(path)
	var layer struct {
		Techniques []struct {
			TechniqueID string `json:"techniqueID"`
			Score       int    `json:"score"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(data, &layer); err != nil {
		t.Fatalf("layer is not valid JSON: %v", err)
	}
	if len(layer.Techniques) != 3 {
		t.Fatalf("expected 3 techniques, got %d", len(layer.Techniques))
	}
	if layer.Techniques[0].Score != 100 {
		t.Errorf("DETECTED technique should score 100, got %d", layer.Techniques[0].Score)
	}
}
