// Command purpleloop is the CLI entrypoint. Uses stdlib flag to keep
// dependencies at zero; ponytail: cobra adds nothing flag doesn't give us.
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
		fmt.Fprintln(os.Stderr, "usage: purpleloop run --technique <ID> [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	technique := fs.String("technique", "", "ATT&CK technique ID, e.g. T1059.004")
	dryRun := fs.Bool("dry-run", false, "run the pipeline without a live lab")
	victim := fs.String("victim-container", "", "Docker container name for execution (e.g. purpleloop-victim)")
	manager := fs.String("manager-container", "", "Docker container name for Wazuh manager")
	_ = fs.Parse(os.Args[2:])

	if *technique == "" {
		fmt.Fprintln(os.Stderr, "error: --technique is required")
		os.Exit(2)
	}
	if err := runOne(context.Background(), *technique, *dryRun, *victim, *manager); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func runOne(ctx context.Context, technique string, dryRun bool, victimContainer, managerContainer string) error {
	var exec model.Executor
	var coll model.Collector

	if dryRun || victimContainer == "" {
		exec = executor.DryExecutor{}
	} else {
		exec = executor.DockerExecutor{Container: victimContainer}
	}

	if dryRun || managerContainer == "" {
		coll = &collector.WazuhCollector{} // dry mode
	} else {
		coll = &collector.WazuhCollector{ManagerContainer: managerContainer}
	}

	eval := evaluator.PresenceEvaluator{}
	rep := report.JSONReporter{Out: os.Stdout}

	atomic := model.AtomicTest{
		ID:          technique + "-1",
		TechniqueID: technique,
		Command:     "id; whoami",
		Executor:    "sh",
	}
	target := model.Target{Host: "victim01", Kind: "linux"}

	run, err := exec.Run(ctx, atomic, target)
	if err != nil {
		return fmt.Errorf("execute: %w", err)
	}
	defer func() {
		if err := exec.Cleanup(ctx, atomic, target); err != nil {
			fmt.Fprintf(os.Stderr, "cleanup warning: %v\n", err)
		}
	}()

	events, err := coll.Query(ctx, run.Window(5*time.Second), target.Host)
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
