// Package feed provides PriorityFeed implementations. StaticFeed reads a fixed
// list (Phase 2); the Phase 4 ArbiterFeed will consume threat-intel-arbiter
// output and sort by priority, satisfying the same interface.
package feed

import (
	"context"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

type StaticFeed struct {
	Tasks []model.TechniqueTask
}

func (f StaticFeed) Next(ctx context.Context) ([]model.TechniqueTask, error) {
	return f.Tasks, nil
}
