package feed

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// EmulationPlan is a multi-stage actor emulation plan.
type EmulationPlan struct {
	Name        string              `yaml:"name"`
	Description string              `yaml:"description"`
	Stages      []EmulationStage    `yaml:"stages"`
}

// EmulationStage is one tactical phase in an emulation plan.
type EmulationStage struct {
	Name        string          `yaml:"name"`
	Description string          `yaml:"description"`
	Techniques  []PlanTechnique `yaml:"techniques"`
}

// EmulationResult holds per-stage results for reporting.
type EmulationResult struct {
	PlanName string
	Stages   []StageResult
}

// StageResult holds the campaign result for one stage.
type StageResult struct {
	Name   string
	Chains []model.ProofChain
}

// LoadEmulation reads a multi-stage emulation plan YAML.
func LoadEmulation(path string) (*EmulationPlan, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read emulation plan: %w", err)
	}
	var plan EmulationPlan
	if err := yaml.Unmarshal(data, &plan); err != nil {
		return nil, fmt.Errorf("parse emulation plan: %w", err)
	}
	return &plan, nil
}

// ToTasks converts a single stage into TechniqueTasks.
func (s EmulationStage) ToTasks() []model.TechniqueTask {
	var tasks []model.TechniqueTask
	for i, t := range s.Techniques {
		tasks = append(tasks, model.TechniqueTask{
			TechniqueID: t.TechniqueID,
			AtomicIDs:   t.AtomicIDs,
			Priority:    float64(len(s.Techniques) - i),
		})
	}
	return tasks
}

// Next satisfies PriorityFeed. Not used directly for emulation.
func (EmulationPlan) Next(ctx context.Context) ([]model.TechniqueTask, error) {
	return nil, fmt.Errorf("use Stages() for emulation plans")
}
