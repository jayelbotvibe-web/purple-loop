// Package canary implements the pipeline positive control.
// A unique per-run marker is executed on each target platform;
// if the canary doesn't fire, the run is INCONCLUSIVE.
package canary

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/evaluator"
	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

const rulePath = "detections/canary/pipeline_canary.yml"

// Result holds the outcome of a canary check on one platform.
type Result struct {
	Platform string
	Marker   string
	Healthy  bool
	Evidence []model.Event
	Err      error
}

// NewMarker generates a fresh 8-hex run-id marker.
func NewMarker() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "purpleloop-canary-" + hex.EncodeToString(b)
}

// Checker verifies the canary marker on one platform. Zero-value fields fall
// back to production defaults; tests override the timing and rule paths.
type Checker struct {
	RulePath     string        // canary Sigma rule (default: rulePath const)
	RulesDir     string        // rules root passed to the evaluator (default: "detections")
	PollInterval time.Duration // gap between telemetry polls (default: 5s)
	Timeout      time.Duration // total time to wait for the marker (default: 90s)
	WindowPad    time.Duration // padding around the run window (default: 2m)
}

func (ck Checker) withDefaults() Checker {
	if ck.RulePath == "" {
		ck.RulePath = rulePath
	}
	if ck.RulesDir == "" {
		ck.RulesDir = "detections"
	}
	if ck.PollInterval == 0 {
		ck.PollInterval = 5 * time.Second
	}
	if ck.Timeout == 0 {
		ck.Timeout = 90 * time.Second
	}
	if ck.WindowPad == 0 {
		ck.WindowPad = 2 * time.Minute
	}
	return ck
}

// Run executes the canary once, then polls telemetry until the marker is
// detected or the timeout elapses. Executing a single time (rather than
// re-firing on every retry) keeps the run window tight and the marker unique.
func (ck Checker) Run(ctx context.Context, marker string, exec model.Executor,
	coll model.Collector, platform string, target model.Target) Result {

	ck = ck.withDefaults()
	r := Result{Platform: platform, Marker: marker}
	atomic := atomicFor(platform, marker)

	run, err := exec.Run(ctx, atomic, target)
	if err != nil {
		r.Err = fmt.Errorf("canary execute: %w", err)
		return r
	}
	defer func() { _ = exec.Cleanup(ctx, atomic, target) }()

	eval := evaluator.RuleMatcherEvaluator{RulesDir: ck.RulesDir}
	rule := model.SigmaRule{Path: ck.RulePath, Title: "Pipeline Canary"}
	window := run.Window(ck.WindowPad)

	deadline := time.Now().Add(ck.Timeout)
	for {
		events, err := coll.Query(ctx, window, target.Host)
		if err != nil {
			r.Err = fmt.Errorf("canary collect: %w", err)
		} else if len(events) > 0 {
			verdict, evidence, err := eval.Evaluate(rule, events)
			switch {
			case err != nil:
				r.Err = fmt.Errorf("canary evaluate: %w", err)
			case verdict == model.Detected && evidenceContainsMarker(evidence, marker):
				r.Healthy = true
				r.Evidence = evidence
				r.Err = nil
				return r
			}
		}

		if time.Now().After(deadline) {
			return r
		}
		select {
		case <-ctx.Done():
			r.Err = ctx.Err()
			return r
		case <-time.After(ck.PollInterval):
		}
	}
}

// Check executes the canary on one platform and verifies the marker was
// detected, using production defaults.
func Check(ctx context.Context, marker string, exec model.Executor,
	coll model.Collector, platform string, target model.Target, dryRun bool) Result {
	return Checker{}.Run(ctx, marker, exec, coll, platform, target)
}

func atomicFor(platform, marker string) model.AtomicTest {
	switch platform {
	case "windows":
		return model.AtomicTest{
			ID:       "canary-win",
			Command:  fmt.Sprintf(`cmd.exe /c "echo %s"`, marker),
			Executor: "sh",
		}
	default:
		return model.AtomicTest{
			ID:       "canary-linux",
			Command:  fmt.Sprintf("echo '%s'", marker),
			Executor: "sh",
		}
	}
}

func evidenceContainsMarker(events []model.Event, marker string) bool {
	for _, ev := range events {
		if len(ev.Raw) == 0 {
			continue
		}
		if contains(ev.Raw, marker) {
			return true
		}
	}
	return false
}

func contains(raw []byte, s string) bool {
	return len(raw) >= len(s) && stringContains(string(raw), s)
}

func stringContains(haystack, needle string) bool {
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
