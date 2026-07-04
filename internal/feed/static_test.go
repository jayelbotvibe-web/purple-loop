package feed

import (
	"context"
	"testing"
)

func TestStaticFeed_Load(t *testing.T) {
	var f StaticFeed
	if err := f.Load("../../plans/discovery.yml"); err != nil {
		t.Fatalf("Load: %v", err)
	}
	tasks, err := f.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if len(tasks) != 10 {
		t.Errorf("got %d tasks, want 10", len(tasks))
	}
	// Verify first task is T1059.004 (first in plan, highest priority)
	if tasks[0].TechniqueID != "T1059.004" {
		t.Errorf("first task = %s, want T1059.004", tasks[0].TechniqueID)
	}
	if tasks[0].Priority != 10 {
		t.Errorf("first priority = %f, want 10", tasks[0].Priority)
	}
	// Verify last task has lowest priority
	if tasks[9].Priority != 1 {
		t.Errorf("last priority = %f, want 1", tasks[9].Priority)
	}
}
