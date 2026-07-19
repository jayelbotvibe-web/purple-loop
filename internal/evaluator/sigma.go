package evaluator

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// RuleMatcherEvaluator evaluates Sigma rules against normalized events.
type RuleMatcherEvaluator struct {
	RulesDir string // e.g. "detections/linux"
}

// Evaluate applies the rule to all events and returns the best verdict.
func (e RuleMatcherEvaluator) Evaluate(rule model.SigmaRule, events []model.Event) (model.Verdict, []model.Event, error) {
	if e.RulesDir == "" {
		e.RulesDir = "detections/linux"
	}

	if len(events) == 0 {
		return model.NoTelemetry, nil, nil
	}

	// Load the rule specified
	rulePath := rule.Path
	if rulePath == "" {
		return model.Missed, nil, nil // no rule mapped for this technique
	}
	if _, err := os.Stat(rulePath); err != nil {
		rulePath = filepath.Join(e.RulesDir, filepath.Base(rule.Path))
	}
	if rulePath == "" || rulePath == e.RulesDir {
		return model.Missed, nil, nil
	}
	if _, err := os.Stat(rulePath); os.IsNotExist(err) {
		// Rule doesn't exist — no detection to evaluate
		return model.Missed, nil, nil
	}

	parser := RuleParser{}
	matcher := Matcher{}
	normalizer := Normalizer{}

	parsedRule, err := parser.Parse(rulePath)
	if err != nil {
		return model.Errored, nil, fmt.Errorf("parse rule %s: %w", rule.Path, err)
	}

	// For process-creation rules, only genuine process-creation telemetry can
	// justify a verdict. Command-output/metadata scrapes (full_log, decoder
	// name) are tagged low fidelity by the normalizer and are excluded here, so
	// a log line that merely mentions a binary can never produce a false
	// DETECTED. See normalizer.go and the Fidelity* constants.
	requireProcess := parsedRule.Category == FidelityProcess

	var matchedEvents []model.Event
	usableEvents := 0
	for _, ev := range events {
		normalized := normalizer.Normalize(ev.Raw)
		if len(normalized) == 0 {
			continue
		}
		if requireProcess && normalized[FidelityKey] != FidelityProcess {
			continue // low-fidelity event cannot be process-creation evidence
		}
		usableEvents++
		if matcher.Match(parsedRule, normalized) {
			matchedEvents = append(matchedEvents, ev)
		}
	}

	if len(matchedEvents) > 0 {
		return model.Detected, matchedEvents, nil
	}
	// No telemetry of the kind this rule needs was collected — that is a
	// collection gap, not a proven detection miss.
	if requireProcess && usableEvents == 0 {
		return model.NoTelemetry, nil, nil
	}
	return model.Missed, nil, nil
}
