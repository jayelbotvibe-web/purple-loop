package collector

import (
	"context"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// Settler polls a collector until the telemetry for an execution has arrived,
// instead of sleeping a fixed amount and hoping.
//
// The pipeline previously slept 10s per technique and then queried once. That
// is wrong in both directions: too long when the SIEM has already indexed the
// events (ten techniques spend 100s asleep), and too short when it has not,
// which produces a NO_TELEMETRY that is really an impatience artifact.
//
// Settle returns as soon as one of three things is true:
//
//   - Satisfied reports a match — nothing later can improve on a detection;
//   - the event count stops growing for StableFor consecutive polls, meaning
//     ingestion has settled and no further events are coming;
//   - Timeout elapses, which is a genuine "the events never arrived".
type Settler struct {
	PollInterval time.Duration // gap between polls (default 3s)
	Timeout      time.Duration // total budget (default 60s)
	StableFor    int           // polls with no new events before settling (default 2)
	MinWait      time.Duration // floor before the first poll (default 2s)
}

func (s Settler) withDefaults() Settler {
	if s.PollInterval <= 0 {
		s.PollInterval = 3 * time.Second
	}
	if s.Timeout <= 0 {
		s.Timeout = 60 * time.Second
	}
	if s.StableFor <= 0 {
		s.StableFor = 2
	}
	if s.MinWait < 0 {
		s.MinWait = 0
	}
	if s.MinWait == 0 {
		s.MinWait = 2 * time.Second
	}
	return s
}

// SettleResult reports what the poll loop observed.
type SettleResult struct {
	Events    []model.Event
	Satisfied bool          // the caller's predicate matched
	Waited    time.Duration // how long collection actually took
	TimedOut  bool
}

// Settle polls coll for the window until satisfied, stable, or timed out.
// satisfied may be nil, in which case Settle waits for ingestion to stabilise.
func (s Settler) Settle(ctx context.Context, coll model.Collector, window model.TimeWindow,
	host string, satisfied func([]model.Event) bool) (SettleResult, error) {

	s = s.withDefaults()
	started := time.Now()
	deadline := started.Add(s.Timeout)

	// A brief floor before the first query: an immediate poll almost always
	// races the SIEM's indexer and wastes a round trip.
	if err := sleepCtx(ctx, s.MinWait); err != nil {
		return SettleResult{}, err
	}

	var last []model.Event
	stable := 0

	for {
		events, err := coll.Query(ctx, window, host)
		if err != nil {
			return SettleResult{Events: last, Waited: time.Since(started)}, err
		}

		if satisfied != nil && satisfied(events) {
			return SettleResult{Events: events, Satisfied: true, Waited: time.Since(started)}, nil
		}

		if len(events) == len(last) {
			stable++
		} else {
			stable = 0
		}
		last = events

		// Ingestion has settled: the count held steady across consecutive polls,
		// so waiting longer cannot change the verdict. Requiring at least one
		// event avoids settling instantly on an empty archive that is merely slow.
		if stable >= s.StableFor && len(events) > 0 {
			return SettleResult{Events: events, Waited: time.Since(started)}, nil
		}

		if time.Now().After(deadline) {
			return SettleResult{Events: events, Waited: time.Since(started), TimedOut: true}, nil
		}
		if err := sleepCtx(ctx, s.PollInterval); err != nil {
			return SettleResult{Events: events, Waited: time.Since(started)}, err
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}
