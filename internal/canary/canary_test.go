package canary

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

type fakeExecutor struct{ ran bool }

func (f *fakeExecutor) Run(context.Context, model.AtomicTest, model.Target) (model.RunResult, error) {
	f.ran = true
	now := time.Now().UTC()
	return model.RunResult{StartedAt: now, FinishedAt: now}, nil
}
func (f *fakeExecutor) Cleanup(context.Context, model.AtomicTest, model.Target) error { return nil }

// fakeCollector returns whatever events it is configured with.
type fakeCollector struct{ events []model.Event }

func (f fakeCollector) Query(context.Context, model.TimeWindow, string) ([]model.Event, error) {
	return f.events, nil
}

func testChecker() Checker {
	return Checker{
		RulePath:     "../../detections/canary/pipeline_canary.yml",
		RulesDir:     "../../detections",
		PollInterval: time.Millisecond,
		Timeout:      20 * time.Millisecond,
	}
}

func TestChecker_HealthyOnProcessTelemetry(t *testing.T) {
	marker := NewMarker()
	raw, _ := json.Marshal(map[string]string{
		"Image":       "C:\\Windows\\System32\\cmd.exe",
		"CommandLine": "cmd.exe /c echo " + marker,
	})
	coll := fakeCollector{events: []model.Event{{ID: "e1", Raw: raw}}}

	r := testChecker().Run(context.Background(), marker, &fakeExecutor{}, coll, "windows", model.Target{Host: "win"})
	if !r.Healthy {
		t.Fatalf("expected healthy canary, got err=%v", r.Err)
	}
	if len(r.Evidence) == 0 {
		t.Error("healthy canary should carry evidence")
	}
}

func TestChecker_NotHealthyWithoutTelemetry(t *testing.T) {
	marker := NewMarker()
	coll := fakeCollector{events: nil}

	r := testChecker().Run(context.Background(), marker, &fakeExecutor{}, coll, "linux", model.Target{Host: "victim"})
	if r.Healthy {
		t.Fatal("no telemetry must not report healthy")
	}
}

// A command-output log echoing the marker is NOT process-creation evidence,
// so the canary must not report the pipeline healthy on it.
func TestChecker_LowFidelityLogIsNotHealthy(t *testing.T) {
	marker := NewMarker()
	raw := json.RawMessage(`{"full_log":"ossec: output: 'echo ` + marker + `': ` + marker + `"}`)
	coll := fakeCollector{events: []model.Event{{ID: "log1", Raw: raw}}}

	r := testChecker().Run(context.Background(), marker, &fakeExecutor{}, coll, "linux", model.Target{Host: "victim"})
	if r.Healthy {
		t.Fatal("low-fidelity command-output must not report the pipeline healthy")
	}
}

func TestNewMarker_Unique(t *testing.T) {
	a, b := NewMarker(), NewMarker()
	if a == b {
		t.Error("markers should be unique")
	}
	if !strings.HasPrefix(a, "purpleloop-canary-") {
		t.Errorf("unexpected marker format: %q", a)
	}
}
