package collector

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// scriptedCollector returns a different event slice on each successive call.
type scriptedCollector struct {
	rounds [][]model.Event
	calls  int
}

func (c *scriptedCollector) Query(ctx context.Context, w model.TimeWindow, host string) ([]model.Event, error) {
	i := c.calls
	c.calls++
	if i >= len(c.rounds) {
		i = len(c.rounds) - 1
	}
	return c.rounds[i], nil
}

func ev(n int) []model.Event {
	out := make([]model.Event, n)
	for i := range out {
		out[i] = model.Event{ID: string(rune('a' + i)), Raw: json.RawMessage(`{}`)}
	}
	return out
}

func fast() Settler {
	return Settler{PollInterval: time.Millisecond, Timeout: 200 * time.Millisecond, StableFor: 2, MinWait: time.Millisecond}
}

// A match ends collection immediately — nothing later can improve on it.
func TestSettleStopsOnSatisfied(t *testing.T) {
	c := &scriptedCollector{rounds: [][]model.Event{ev(1), ev(2), ev(3)}}
	res, err := fast().Settle(context.Background(), c, model.TimeWindow{}, "h",
		func(e []model.Event) bool { return len(e) >= 2 })
	if err != nil {
		t.Fatal(err)
	}
	if !res.Satisfied {
		t.Error("want Satisfied")
	}
	if c.calls != 2 {
		t.Errorf("polled %d times, want 2 — it should stop as soon as the predicate matches", c.calls)
	}
}

// Once the count holds steady, ingestion has settled and waiting longer cannot
// change the verdict.
func TestSettleStopsWhenStable(t *testing.T) {
	c := &scriptedCollector{rounds: [][]model.Event{ev(1), ev(2), ev(2), ev(2)}}
	res, err := fast().Settle(context.Background(), c, model.TimeWindow{}, "h", func([]model.Event) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if res.Satisfied || res.TimedOut {
		t.Errorf("want a settled result, got satisfied=%v timedout=%v", res.Satisfied, res.TimedOut)
	}
	if len(res.Events) != 2 {
		t.Errorf("events = %d, want 2", len(res.Events))
	}
}

// An archive that never produces an event must time out rather than settle at
// zero: "nothing arrived yet" and "nothing will arrive" are different claims,
// and only the timeout can distinguish them.
func TestSettleDoesNotSettleOnEmpty(t *testing.T) {
	c := &scriptedCollector{rounds: [][]model.Event{{}}}
	res, err := fast().Settle(context.Background(), c, model.TimeWindow{}, "h", func([]model.Event) bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Error("an always-empty archive must time out, not settle")
	}
	if len(res.Events) != 0 {
		t.Errorf("events = %d, want 0", len(res.Events))
	}
}

func TestSettleRespectsContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c := &scriptedCollector{rounds: [][]model.Event{{}}}
	if _, err := fast().Settle(ctx, c, model.TimeWindow{}, "h", nil); err == nil {
		t.Error("a cancelled context must abort collection")
	}
}
