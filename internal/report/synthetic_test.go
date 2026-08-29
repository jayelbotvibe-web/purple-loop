package report

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// TestDashboard_SyntheticNotPublished guards that a synthetic (dry) run writes
// a marked per-run artifact but is NEVER appended to history or published to the
// public docs/data snapshot.
func TestDashboard_SyntheticNotPublished(t *testing.T) {
	tmp := t.TempDir()
	old, _ := os.Getwd()
	defer os.Chdir(old)
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}

	r := DashboardReporter{Dir: "reports"}
	result := model.CampaignResult{
		StartedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Synthetic: true,
		Chains:    []model.ProofChain{{TechniqueID: "T1", Verdict: model.Detected}},
	}
	if err := r.Write(result); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := os.Stat("docs/data/coverage.json"); !os.IsNotExist(err) {
		t.Error("synthetic run must NOT publish docs/data/coverage.json")
	}
	if _, err := os.Stat(filepath.Join("reports", "history.json")); !os.IsNotExist(err) {
		t.Error("synthetic run must NOT append to history.json")
	}
	if runs, _ := filepath.Glob("reports/runs/*/coverage.json"); len(runs) != 1 {
		t.Errorf("expected 1 marked per-run artifact, got %d", len(runs))
	}
}

// TestBuildCoverage_CanaryReflectsResult guards that the dashboard canary flag
// is the REAL result, never hardcoded true.
func TestBuildCoverage_CanaryReflectsResult(t *testing.T) {
	inc := buildCoverage(model.CampaignResult{Inconclusive: true})
	if inc["canary"].(map[string]any)["healthy"].(bool) {
		t.Error("inconclusive run must report canary healthy=false")
	}
	syn := buildCoverage(model.CampaignResult{CanaryHealthy: true, Synthetic: true})
	if syn["canary"].(map[string]any)["healthy"].(bool) {
		t.Error("synthetic run must report canary healthy=false")
	}
	real := buildCoverage(model.CampaignResult{CanaryHealthy: true})
	if !real["canary"].(map[string]any)["healthy"].(bool) {
		t.Error("healthy real run must report canary healthy=true")
	}
}

// TestHTML_SyntheticBanner guards the loud non-evidentiary banner in the HTML report.
func TestHTML_SyntheticBanner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "r.html")
	if err := (HTMLReporter{Path: path}).Write(model.CampaignResult{Synthetic: true}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	if !strings.Contains(string(b), "SYNTHETIC") {
		t.Error("HTML report of a synthetic run must show a SYNTHETIC banner")
	}
}
