// Package evaluator decides whether collected events satisfy a detection.
// PresenceEvaluator is a placeholder (DETECTED if any events, else MISSED);
// Phase 1 replaces it with real Sigma matching.
package evaluator

import "github.com/jayelbotvibe-web/purple-loop/internal/model"

type PresenceEvaluator struct{}

func (PresenceEvaluator) Evaluate(rule model.SigmaRule, events []model.Event) (model.Verdict, []model.Event, error) {
	if len(events) == 0 {
		return model.Missed, nil, nil
	}
	// Phase 1: parse the Sigma rule and match its detection logic against each
	// event; return the matching events as evidence.
	return model.Detected, events, nil
}
