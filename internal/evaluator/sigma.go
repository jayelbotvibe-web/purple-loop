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

	// Evaluate each event
	var matchedEvents []model.Event
	for _, ev := range events {
		normalized := normalizer.Normalize(ev.Raw)
		if len(normalized) == 0 {
			continue
		}
		if matcher.Match(parsedRule, normalized) {
			matchedEvents = append(matchedEvents, ev)
		}
	}

	if len(matchedEvents) > 0 {
		return model.Detected, matchedEvents, nil
	}
	return model.Missed, nil, nil
}
