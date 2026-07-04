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
	"github.com/jayelbotvibe-web/purple-loop/internal/feed"
	"github.com/jayelbotvibe-web/purple-loop/internal/model"
	"github.com/jayelbotvibe-web/purple-loop/internal/report"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: purpleloop run [--technique <ID> | --plan <file>] [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	technique := fs.String("technique", "", "Single technique ID, e.g. T1059.004")
	planFile := fs.String("plan", "", "YAML plan file (e.g. plans/discovery.yml)")
	output := fs.String("output", "", "Output file (.html for coverage report, empty = JSON stdout)")
	dryRun := fs.Bool("dry-run", false, "run the pipeline without a live lab")
	victim := fs.String("victim-container", "", "Docker container for execution (e.g. purpleloop-victim)")
	manager := fs.String("manager-container", "", "Docker container for Wazuh manager")
	_ = fs.Parse(os.Args[2:])

	ctx := context.Background()

	switch {
	case *planFile != "":
		if err := runCampaign(ctx, *planFile, *output, *dryRun, *victim, *manager); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case *technique != "":
		if err := runOne(ctx, *technique, *output, *dryRun, *victim, *manager); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	default:
		fmt.Fprintln(os.Stderr, "error: --technique or --plan is required")
		os.Exit(2)
	}
}

func newExec(dryRun bool, victimContainer string) model.Executor {
	if dryRun || victimContainer == "" {
		return executor.DryExecutor{}
	}
	return executor.DockerExecutor{Container: victimContainer}
}

func newColl(dryRun bool, managerContainer string) model.Collector {
	if dryRun || managerContainer == "" {
		return &collector.WazuhCollector{}
	}
	return &collector.WazuhCollector{ManagerContainer: managerContainer}
}

func newReporter(output string) model.Reporter {
	if output != "" {
		return report.HTMLReporter{Path: output}
	}
	return report.JSONReporter{Out: os.Stdout}
}

func runCampaign(ctx context.Context, planPath, output string, dryRun bool, victimContainer, managerContainer string) error {
	var f feed.StaticFeed
	if err := f.Load(planPath); err != nil {
		return fmt.Errorf("load plan: %w", err)
	}
	tasks, err := f.Next(ctx)
	if err != nil {
		return fmt.Errorf("feed: %w", err)
	}

	exec := newExec(dryRun, victimContainer)
	coll := newColl(dryRun, managerContainer)
	eval := evaluator.PresenceEvaluator{}
	rep := newReporter(output)
	target := model.Target{Host: "victim01", Kind: "linux"}

	result := model.CampaignResult{StartedAt: time.Now().UTC()}
	for _, task := range tasks {
		chain, err := runTechnique(ctx, exec, coll, eval, task, target)
		if err != nil {
			chain = model.ProofChain{
				TechniqueID: task.TechniqueID,
				Verdict:     model.Errored,
			}
		}
		result.Chains = append(result.Chains, chain)
	}
	return rep.Write(result)
}

func runOne(ctx context.Context, technique, output string, dryRun bool, victimContainer, managerContainer string) error {
	exec := newExec(dryRun, victimContainer)
	coll := newColl(dryRun, managerContainer)
	eval := evaluator.PresenceEvaluator{}
	rep := newReporter(output)

	task := model.TechniqueTask{TechniqueID: technique, AtomicIDs: []string{technique + "-1"}}
	target := model.Target{Host: "victim01", Kind: "linux"}

	chain, err := runTechnique(ctx, exec, coll, eval, task, target)
	if err != nil {
		return err
	}
	return rep.Write(model.CampaignResult{StartedAt: time.Now().UTC(), Chains: []model.ProofChain{chain}})
}

func runTechnique(ctx context.Context, exec model.Executor, coll model.Collector, eval model.Evaluator, task model.TechniqueTask, target model.Target) (model.ProofChain, error) {
	atomicID := task.TechniqueID + "-1"
	if len(task.AtomicIDs) > 0 {
		atomicID = task.AtomicIDs[0]
	}

	atomic := model.AtomicTest{
		ID:          atomicID,
		TechniqueID: task.TechniqueID,
		Command:     "id; whoami",
		Executor:    "sh",
	}

	run, err := exec.Run(ctx, atomic, target)
	if err != nil {
		return model.ProofChain{}, fmt.Errorf("execute: %w", err)
	}
	// ponytail: cleanup is best-effort per atomic after run
	_ = exec.Cleanup(ctx, atomic, target)

	events, err := coll.Query(ctx, run.Window(5*time.Second), target.Host)
	if err != nil {
		return model.ProofChain{}, fmt.Errorf("collect: %w", err)
	}

	rule := model.SigmaRule{Path: "detections/linux/proc_creation_susp_shell.yml", Title: "Suspicious shell"}
	verdict, evidence, err := eval.Evaluate(rule, events)
	if err != nil {
		return model.ProofChain{}, fmt.Errorf("evaluate: %w", err)
	}

	return model.ProofChain{
		TechniqueID:     task.TechniqueID,
		Atomic:          atomic,
		ExecutedAt:      run.StartedAt,
		EventsCollected: len(events),
		RuleMatched:     rule.Path,
		Verdict:         verdict,
		Evidence:        evidence,
	}, nil
}
