package capture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func sampleRun(synthetic bool) model.CampaignResult {
	start := time.Date(2026, 8, 29, 10, 0, 0, 0, time.UTC)
	mk := func(tech, atomicID string, n int) model.ProofChain {
		evs := make([]model.Event, n)
		for i := range evs {
			evs[i] = model.Event{
				ID:        tech + "-ev",
				Timestamp: start.Add(time.Duration(i) * time.Second),
				Raw:       json.RawMessage(`{"Image":"/usr/bin/uname","CommandLine":"uname -a"}`),
			}
		}
		return model.ProofChain{
			TechniqueID: tech,
			Atomic:      model.AtomicTest{ID: atomicID, TechniqueID: tech},
			ExecutedAt:  start,
			Window:      model.TimeWindow{Start: start, End: start.Add(time.Minute)},
			Collected:   evs,
		}
	}
	return model.CampaignResult{
		StartedAt: start,
		Synthetic: synthetic,
		Chains:    []model.ProofChain{mk("T1082", "T1082-3", 2), mk("T1033", "T1033-2", 1)},
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, sampleRun(false), "victim01"); err != nil {
		t.Fatalf("write: %v", err)
	}
	ds, err := Read(dir)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(ds.Records) != 3 {
		t.Fatalf("records = %d, want 3", len(ds.Records))
	}

	order, events, meta := ds.ByTechnique()
	if len(order) != 2 || order[0] != "T1082" {
		t.Errorf("order = %v, want T1082 first (campaign sequence preserved)", order)
	}
	if len(events["T1082"]) != 2 || len(events["T1033"]) != 1 {
		t.Errorf("grouping wrong: %d/%d", len(events["T1082"]), len(events["T1033"]))
	}
	if meta["T1082"].AtomicID != "T1082-3" {
		t.Errorf("atomic = %q, want T1082-3 — replay needs the atomic that produced the events",
			meta["T1082"].AtomicID)
	}
	if meta["T1082"].Host != "victim01" {
		t.Errorf("host = %q, want victim01", meta["T1082"].Host)
	}
	if meta["T1082"].Window.Start.IsZero() {
		t.Error("the collection window must survive capture")
	}
}

// A synthetic run's telemetry is fabricated. Capturing it would produce a
// dataset indistinguishable from a real one on replay, so it is refused.
func TestWriteRefusesSyntheticRun(t *testing.T) {
	dir := t.TempDir()
	if err := Write(dir, sampleRun(true), "victim01"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Read(dir); err == nil {
		t.Error("a synthetic run must not produce a replayable dataset")
	}
}

func TestReadRejectsEmptyAndMissing(t *testing.T) {
	if _, err := Read(filepath.Join(t.TempDir(), "nope")); err == nil {
		t.Error("a missing dataset must error")
	}
}

// The raw event must survive byte-for-byte: replay re-runs the real matcher
// over it, so any normalisation here would change the verdict.
func TestRawEventPreservedExactly(t *testing.T) {
	dir := t.TempDir()
	run := sampleRun(false)
	want := string(run.Chains[0].Collected[0].Raw)

	if err := Write(dir, run, "victim01"); err != nil {
		t.Fatal(err)
	}
	ds, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(ds.Records[0].Event.Raw); got != want {
		t.Errorf("raw event changed through capture:\n got %s\nwant %s", got, want)
	}
}

// A run that collected nothing must not leave an empty file that looks like a
// dataset but that Read rejects.
func TestWriteSkipsRunWithNoEvents(t *testing.T) {
	dir := t.TempDir()
	run := model.CampaignResult{
		StartedAt: time.Now(),
		Chains:    []model.ProofChain{{TechniqueID: "T1082", Verdict: model.NoTelemetry}},
	}
	if err := Write(dir, run, "victim01"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, Filename)); !os.IsNotExist(err) {
		t.Error("a run with no collected events must not write a dataset file")
	}
}
