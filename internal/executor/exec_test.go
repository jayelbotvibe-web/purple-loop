package executor

import (
	"context"
	"testing"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func TestDockerExecutor_DryRun(t *testing.T) {
	e := DockerExecutor{} // no container => dry
	test := model.AtomicTest{
		ID:       "T1059.004-1",
		Command:  "id",
		Executor: "sh",
	}
	result, err := e.Run(context.Background(), test, model.Target{Host: "victim01"})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Command != "id" {
		t.Errorf("command = %q, want 'id'", result.Command)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() {
		t.Error("timestamps missing")
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
}

func TestDockerExecutor_Cleanup_DryRun(t *testing.T) {
	e := DockerExecutor{} // no container => dry
	test := model.AtomicTest{
		ID:             "T1059.004-1",
		Command:        "touch /tmp/test",
		CleanupCommand: "rm -f /tmp/test",
		Executor:       "sh",
	}
	if err := e.Cleanup(context.Background(), test, model.Target{Host: "victim01"}); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
}

func TestDryExecutor_Run(t *testing.T) {
	e := DryExecutor{}
	test := model.AtomicTest{ID: "T000", Command: "true", Executor: "sh"}
	result, err := e.Run(context.Background(), test, model.Target{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit = %d", result.ExitCode)
	}
}
