// Package capture persists the raw telemetry a campaign collected, so a run can
// be re-evaluated later without a lab.
//
// This is what makes rule changes testable against reality. CI has fixtures —
// events hand-written to prove a rule matches what its author intended — but a
// fixture is a claim about the world, not a sample of it. A captured run lets
// the same matcher be re-run over telemetry the lab actually produced, and lets
// a rule edit be checked against every past run: "would this have broken a
// DETECTED we already had?"
package capture

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// Filename is the dataset written beside a run's coverage.json.
const Filename = "events.jsonl"

// Record is one collected event with the execution it belongs to. The atomic
// and window travel with the event so a replay can reproduce the exact
// evaluation, not merely re-match a pile of logs.
type Record struct {
	TechniqueID string           `json:"technique_id"`
	AtomicID    string           `json:"atomic_id"`
	Host        string           `json:"host"`
	ExecutedAt  time.Time        `json:"executed_at"`
	Window      model.TimeWindow `json:"window"`
	Event       model.Event      `json:"event"`
}

// Dataset is a replayable run, grouped by technique.
type Dataset struct {
	Records []Record
}

// Write persists every collected event for a campaign to dir/events.jsonl.
// A synthetic run is refused: its "telemetry" is fabricated, and a fabricated
// dataset replayed later would be indistinguishable from a real one.
func Write(dir string, run model.CampaignResult, host string) error {
	if run.Synthetic {
		return nil
	}

	// No events means no dataset. Writing an empty file would leave something
	// that looks like a capture but that Read rejects — the run's own report
	// already records that nothing was collected.
	total := 0
	for _, c := range run.Chains {
		total += len(c.Collected)
	}
	if total == 0 {
		return nil
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.Create(filepath.Join(dir, Filename))
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, c := range run.Chains {
		for _, e := range c.Collected {
			rec := Record{
				TechniqueID: c.TechniqueID,
				AtomicID:    c.Atomic.ID,
				Host:        host,
				ExecutedAt:  c.ExecutedAt,
				Window:      c.Window,
				Event:       e,
			}
			if err := enc.Encode(rec); err != nil {
				return err
			}
		}
	}
	return w.Flush()
}

// Read loads a captured dataset. dir may be the run directory or the file.
func Read(path string) (*Dataset, error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		path = filepath.Join(path, Filename)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dataset: %w", err)
	}
	defer f.Close()

	ds := &Dataset{}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // archive events can be large
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("dataset line %d: %w", line, err)
		}
		ds.Records = append(ds.Records, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read dataset: %w", err)
	}
	if len(ds.Records) == 0 {
		return nil, fmt.Errorf("dataset %s is empty", path)
	}
	return ds, nil
}

// ByTechnique groups the dataset's events, preserving first-seen order so a
// replay reproduces the original campaign's sequence.
func (d *Dataset) ByTechnique() ([]string, map[string][]model.Event, map[string]Record) {
	var order []string
	events := map[string][]model.Event{}
	meta := map[string]Record{}
	for _, r := range d.Records {
		if _, seen := events[r.TechniqueID]; !seen {
			order = append(order, r.TechniqueID)
			meta[r.TechniqueID] = r
		}
		events[r.TechniqueID] = append(events[r.TechniqueID], r.Event)
	}
	return order, events, meta
}
