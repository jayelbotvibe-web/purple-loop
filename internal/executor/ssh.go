package executor

import (
	"context"
	"fmt"
	"os/exec"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// SSHExecutor runs atomics via SSH on remote targets (Windows VM, etc).
// Uses sshpass for password auth in lab environments.
type SSHExecutor struct {
	Host     string // e.g. 192.168.88.13
	User     string // e.g. windows-vm
	Password string
}

func (e SSHExecutor) Run(ctx context.Context, test model.AtomicTest, target model.Target) (model.RunResult, error) {
	if e.Host == "" {
		return dryRun(test), nil
	}
	start := time.Now().UTC()
	cmd := exec.CommandContext(ctx, "sshpass", "-p", e.Password,
		"ssh", "-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("%s@%s", e.User, e.Host),
		test.Command)
	out, err := cmd.CombinedOutput()
	finished := time.Now().UTC()
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			return model.RunResult{}, fmt.Errorf("ssh: %w", err)
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

func (e SSHExecutor) Cleanup(ctx context.Context, test model.AtomicTest, target model.Target) error {
	if e.Host == "" || test.CleanupCommand == "" {
		return nil
	}
	cmd := exec.CommandContext(ctx, "sshpass", "-p", e.Password,
		"ssh", "-o", "StrictHostKeyChecking=no",
		fmt.Sprintf("%s@%s", e.User, e.Host),
		test.CleanupCommand)
	return cmd.Run()
}
