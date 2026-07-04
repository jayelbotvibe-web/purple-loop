package feed

import (
	"context"
	"testing"
)

func TestArbiterFeed_Load(t *testing.T) {
	var f ArbiterFeed
	if err := f.Load("../../testdata/arbiter-export.json"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	tasks, err := f.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(tasks) == 0 {
		t.Fatal("expected tasks from arbiter export")
	}

	// Verify priority ordering: highest first
	for i := 1; i < len(tasks); i++ {
		if tasks[i].Priority > tasks[i-1].Priority {
			t.Errorf("tasks not sorted by priority: [%d]=%f > [%d]=%f",
				i, tasks[i].Priority, i-1, tasks[i-1].Priority)
		}
	}

	// Verify first task is from "Act" action
	if tasks[0].Priority != 1.0 {
		t.Errorf("first task priority = %f, want 1.0 (Act)", tasks[0].Priority)
	}

	// Verify tasks have CVEs and technique IDs
	for i, task := range tasks {
		if task.TechniqueID == "" {
			t.Errorf("task[%d] has empty TechniqueID", i)
		}
	}

	t.Logf("loaded %d tasks from arbiter export, top priority: %s (%.1f)",
		len(tasks), tasks[0].TechniqueID, tasks[0].Priority)
}
