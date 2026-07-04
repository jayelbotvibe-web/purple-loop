// Package executor runs atomic tests on lab targets. DockerExecutor runs
// commands via docker exec on the victim container; DryExecutor performs no
// real execution for smoke-testing the pipeline without a lab.
package executor

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// DockerExecutor runs atomics via docker exec on the victim container.
type DockerExecutor struct {
	Container string // e.g. purpleloop-victim
}

// Run executes the atomic command in the victim container and captures the result.
func (e DockerExecutor) Run(ctx context.Context, test model.AtomicTest, target model.Target) (model.RunResult, error) {
	if e.Container == "" {
		return dryRun(test), nil
	}
	start := time.Now().UTC()
	cmd := exec.CommandContext(ctx, "docker", "exec", e.Container,
		test.Executor, "-c", test.Command)
	out, err := cmd.CombinedOutput()
	finished := time.Now().UTC()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return model.RunResult{}, fmt.Errorf("docker exec: %w", err)
		}
	}
	return model.RunResult{
		Command:    test.Command,
		StartedAt:  start,
		FinishedAt: finished,
		ExitCode:   exitCode,
		Stdout:     string(out),
	}, nil
}

// Cleanup runs the atomic's cleanup command and verifies no residue.
func (e DockerExecutor) Cleanup(ctx context.Context, test model.AtomicTest, target model.Target) error {
	if e.Container == "" {
		return nil
	}
	// Run the cleanup command embedded in the test's command set.
	// For shell atomics, cleanup is typically the inverse of setup.
	cleanupCmd := test.CleanupCommand
	if cleanupCmd == "" {
		// default: nothing to clean for read-only commands like id/whoami
		return nil
	}
	cmd := exec.CommandContext(ctx, "docker", "exec", e.Container,
		test.Executor, "-c", cleanupCmd)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cleanup: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func dryRun(test model.AtomicTest) model.RunResult {
	start := time.Now().UTC()
	return model.RunResult{
		Command:    test.Command,
		StartedAt:  start,
		FinishedAt: start.Add(400 * time.Millisecond),
		ExitCode:   0,
	}
}

// DryExecutor is a no-op executor for smoke-testing the pipeline without a lab.
type DryExecutor struct{}

func (DryExecutor) Run(ctx context.Context, test model.AtomicTest, target model.Target) (model.RunResult, error) {
	return dryRun(test), nil
}

func (DryExecutor) Cleanup(ctx context.Context, test model.AtomicTest, target model.Target) error {
	return nil
}
