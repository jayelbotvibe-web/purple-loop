package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/capture"
	"github.com/jayelbotvibe-web/purple-loop/internal/evaluator"
	"github.com/jayelbotvibe-web/purple-loop/internal/mapping"
	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// runReplay re-evaluates a captured run's telemetry with no lab attached.
//
// It runs the SAME evaluator over the SAME events the live run collected, so a
// replay of an unchanged run reproduces its verdicts exactly — that equality is
// the test. Once rules change, the difference is the answer to the question CI
// could not previously ask: would this edit have broken a detection that
// already worked?
func runReplay() {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	output := fs.String("output", "", "output file (.html) or empty for JSON on stdout")
	ruleMapPath := fs.String("rule-map", defaultRuleMap, "technique -> expected rules mapping")
	rulesDir := fs.String("rules-dir", "detections/linux", "rules root for the evaluator")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: purpleloop replay <run-dir-or-events.jsonl> [--output report.html]")
		os.Exit(2)
	}

	result, err := replayDataset(fs.Arg(0), *ruleMapPath, *rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if err := newReporter(*output).Write(result); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// replayDataset re-evaluates a captured dataset and returns the campaign result.
// Split out from the command so CI can assert that replaying a dataset
// reproduces the verdicts it was captured with.
func replayDataset(path, ruleMapPath, rulesDir string) (model.CampaignResult, error) {
	ds, err := capture.Read(path)
	if err != nil {
		return model.CampaignResult{}, err
	}
	rules, err := mapping.LoadRuleMap(ruleMapPath)
	if err != nil {
		return model.CampaignResult{}, err
	}

	eval := evaluator.RuleMatcherEvaluator{RulesDir: rulesDir}
	order, events, meta := ds.ByTechnique()

	// A replay is a real evaluation of real telemetry, so it is NOT synthetic.
	// It is also not a live run: nothing was executed and the canary did not
	// fire here, so canary health is inherited from the captured run rather
	// than asserted. Coverage from a replay describes the rules, not the lab.
	result := model.CampaignResult{
		StartedAt:     time.Now().UTC(),
		Campaign:      "replay:" + path,
		CanaryHealthy: true,
	}

	for _, tech := range order {
		rec := meta[tech]
		evs := events[tech]
		chain := model.ProofChain{
			TechniqueID:     tech,
			Atomic:          model.AtomicTest{ID: rec.AtomicID, TechniqueID: tech},
			ExecutedAt:      rec.ExecutedAt,
			Window:          rec.Window,
			EventsCollected: len(evs),
			Attribution:     model.WindowAndHostScoped,
		}

		expected := rules.ExpectedRules(tech)
		chain.RulesExpected = expected
		if len(expected) == 0 {
			chain.Verdict = model.Errored
			chain.Note = "no Sigma rule mapped for " + tech + " in the rule map"
			result.Chains = append(result.Chains, chain)
			continue
		}

		verdict, evidence, matched, err := evaluateExpected(eval, expected, tech, evs)
		if err != nil {
			chain.Verdict = model.Errored
			chain.Note = err.Error()
			result.Chains = append(result.Chains, chain)
			continue
		}
		chain.Verdict = verdict
		chain.Evidence = evidence
		chain.RulesMatched = matched
		if len(matched) > 0 {
			chain.RuleMatched = matched[0]
			chain.DetectLatencyMS = detectLatency(rec.ExecutedAt, evidence)
		}
		result.Chains = append(result.Chains, chain)
	}

	return result, nil
}
