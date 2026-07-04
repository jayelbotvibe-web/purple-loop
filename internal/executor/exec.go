// Package executor runs atomic tests on lab targets. DryExecutor performs no
// real execution so the CLI runs end-to-end without a lab; the real ssh/WinRM
// executors (Phase 1/3) satisfy the same model.Executor interface.
package executor

import (
	"context"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

type DryExecutor struct{}

func (DryExecutor) Run(ctx context.Context, test model.AtomicTest, target model.Target) (model.RunResult, error) {
	start := time.Now().UTC()
	// Phase 1: open ssh/exec into target.Host, run test.Command with
	// test.Executor, capture stdout/stderr/exit code.
	return model.RunResult{
		Command:    test.Command,
		StartedAt:  start,
		FinishedAt: start.Add(400 * time.Millisecond),
		ExitCode:   0,
	}, nil
}

func (DryExecutor) Cleanup(ctx context.Context, test model.AtomicTest, target model.Target) error {
	// Phase 1: run the atomic's Cleanup and verify no residue.
	return nil
}
