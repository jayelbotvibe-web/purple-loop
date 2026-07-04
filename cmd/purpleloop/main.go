// Command purpleloop is the CLI entrypoint. Skeleton note: uses stdlib flag so
// it compiles with zero external deps; Phase 1 migrates to cobra and swaps the
// dry executor/collector for the real lab implementations.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/collector"
	"github.com/jayelbotvibe-web/purple-loop/internal/evaluator"
	"github.com/jayelbotvibe-web/purple-loop/internal/executor"
	"github.com/jayelbotvibe-web/purple-loop/internal/model"
	"github.com/jayelbotvibe-web/purple-loop/internal/report"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: purpleloop run --technique <ID> [--dry-run]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	technique := fs.String("technique", "", "ATT&CK technique ID, e.g. T1059.004")
	_ = fs.Bool("dry-run", false, "run the pipeline without a live lab")
	wazuhURL := fs.String("wazuh-url", "", "Wazuh API base URL (empty => dry collector)")
	_ = fs.Parse(os.Args[2:])

	if *technique == "" {
		fmt.Fprintln(os.Stderr, "error: --technique is required")
		os.Exit(2)
	}
	if err := runOne(context.Background(), *technique, *wazuhURL); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runOne drives the core loop for a single technique:
// select -> execute -> collect -> evaluate -> proof chain -> report.
func runOne(ctx context.Context, technique, wazuhURL string) error {
	var exec model.Executor = executor.DryExecutor{}
	var coll model.Collector = &collector.WazuhCollector{BaseURL: wazuhURL}
	var eval model.Evaluator = evaluator.PresenceEvaluator{}
	var rep model.Reporter = report.JSONReporter{Out: os.Stdout}

	atomic := model.AtomicTest{
		ID:          technique + "-1",
		TechniqueID: technique,
		Command:     "sh -c 'id; whoami'",
		Executor:    "bash",
	}
	target := model.Target{Host: "victim01", Kind: "linux"}

	run, err := exec.Run(ctx, atomic, target)
	if err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	defer exec.Cleanup(ctx, atomic, target)

	events, err := coll.Query(ctx, run.Window(3*time.Second), target.Host)
	if err != nil {
		return fmt.Errorf("collect: %w", err)
	}

	rule := model.SigmaRule{Path: "detections/linux/proc_creation_susp_shell.yml", Title: "Suspicious shell"}
	verdict, evidence, err := eval.Evaluate(rule, events)
	if err != nil {
		return fmt.Errorf("evaluate: %w", err)
	}

	chain := model.ProofChain{
		TechniqueID:     technique,
		Atomic:          atomic,
		ExecutedAt:      run.StartedAt,
		EventsCollected: len(events),
		RuleMatched:     rule.Path,
		Verdict:         verdict,
		Evidence:        evidence,
	}
	return rep.Write(model.CampaignResult{StartedAt: time.Now().UTC(), Chains: []model.ProofChain{chain}})
}
