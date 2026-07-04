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

// Check executes the canary on one platform and verifies the marker was detected.
func Check(ctx context.Context, marker string, exec model.Executor,
	coll model.Collector, platform string, target model.Target, dryRun bool) Result {

	r := Result{Platform: platform, Marker: marker}

	// Build the canary atomic
	atomic := atomicFor(platform, marker)

	// Execute with 3-try bounded retry for ingestion lag
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				r.Err = ctx.Err()
				return r
			case <-time.After(time.Duration(attempt+1) * 5 * time.Second):
			}
		}

		run, err := exec.Run(ctx, atomic, target)
		if err != nil {
			r.Err = fmt.Errorf("canary execute: %w", err)
			continue
		}
		_ = exec.Cleanup(ctx, atomic, target)

		time.Sleep(10 * time.Second) // ingest delay

		events, err := coll.Query(ctx, run.Window(2*time.Minute), target.Host)
		if err != nil {
			r.Err = fmt.Errorf("canary collect: %w", err)
			continue
		}
		if len(events) == 0 {
			continue
		}

		// Evaluate canary rule
		eval := evaluator.RuleMatcherEvaluator{RulesDir: "detections"}
		rule := model.SigmaRule{Path: rulePath, Title: "Pipeline Canary"}
		verdict, evidence, err := eval.Evaluate(rule, events)
		if err != nil {
			r.Err = fmt.Errorf("canary evaluate: %w", err)
			continue
		}

		// Must be DETECTED AND contain exact marker
		if verdict == model.Detected && evidenceContainsMarker(evidence, marker) {
			r.Healthy = true
			r.Evidence = evidence
			return r
		}
	}

	return r
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
