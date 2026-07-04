// Package feed provides PriorityFeed implementations. StaticFeed reads a
// fixed plan from a YAML file; Phase 4 ArbiterFeed consumes arbiter output.
package feed

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// Plan is the YAML schema for a technique validation campaign.
type Plan struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	Techniques  []PlanTechnique `yaml:"techniques"`
}

// PlanTechnique is one technique entry in the plan YAML.
type PlanTechnique struct {
	TechniqueID string   `yaml:"technique_id"`
	AtomicIDs   []string `yaml:"atomic_ids"`
}

// StaticFeed yields tasks from a YAML plan file.
type StaticFeed struct {
	Tasks []model.TechniqueTask
}

// Load reads a plan YAML file and populates the feed's task list.
func (f *StaticFeed) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read plan: %w", err)
	}
	var plan Plan
	if err := yaml.Unmarshal(data, &plan); err != nil {
		return fmt.Errorf("parse plan: %w", err)
	}
	f.Tasks = make([]model.TechniqueTask, 0, len(plan.Techniques))
	for i, t := range plan.Techniques {
		f.Tasks = append(f.Tasks, model.TechniqueTask{
			TechniqueID: t.TechniqueID,
			AtomicIDs:   t.AtomicIDs,
			Priority:    float64(len(plan.Techniques) - i), // simple: first = highest
		})
	}
	return nil
}

// Next returns all tasks in order.
func (f StaticFeed) Next(ctx context.Context) ([]model.TechniqueTask, error) {
	return f.Tasks, nil
}
