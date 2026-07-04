package collector

import (
	"context"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func TestWazuhCollector_Query_Fixture(t *testing.T) {
	c := &WazuhCollector{
		alertsPath: "testdata/alerts.jsonl",
	}

	// Time window covering all fixture data (2026-07-04)
	start, _ := time.Parse(time.RFC3339, "2026-07-04T00:00:00Z")
	end, _ := time.Parse(time.RFC3339, "2026-07-05T00:00:00Z")
	window := model.TimeWindow{Start: start, End: end}

	events, err := c.Query(context.Background(), window, "victim01")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("expected events from fixture, got 0")
	}

	// Every event should have an ID, timestamp, and raw payload
	for i, e := range events {
		if e.ID == "" {
			t.Errorf("event[%d] has empty ID", i)
		}
		if e.Timestamp.IsZero() {
			t.Errorf("event[%d] has zero timestamp", i)
		}
		if len(e.Raw) == 0 {
			t.Errorf("event[%d] has empty Raw", i)
		}
	}

	t.Logf("collected %d events from fixture for victim01", len(events))
}

func TestWazuhCollector_Query_FilterByTime(t *testing.T) {
	c := &WazuhCollector{
		alertsPath: "testdata/alerts.jsonl",
	}

	// Window before any fixture data — should return empty, not nil
	farPast := model.TimeWindow{
		Start: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		End:   time.Date(2020, 1, 2, 0, 0, 0, 0, time.UTC),
	}
	events, err := c.Query(context.Background(), farPast, "victim01")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if events == nil {
		t.Error("expected empty slice, got nil")
	}
	if len(events) != 0 {
		t.Errorf("expected 0 events for far-past window, got %d", len(events))
	}
}

func TestWazuhCollector_Query_DryMode(t *testing.T) {
	c := &WazuhCollector{} // no ManagerContainer, no alertsPath => dry

	window := model.TimeWindow{
		Start: time.Now().Add(-time.Hour),
		End:   time.Now(),
	}
	events, err := c.Query(context.Background(), window, "victim01")
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(events) != 1 || events[0].ID != "dry-0001" {
		t.Errorf("dry mode: expected 1 synthetic event, got %d", len(events))
	}
}
