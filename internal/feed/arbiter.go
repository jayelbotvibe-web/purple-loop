package feed

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// SSVC action to priority score mapping.
var actionPriority = map[string]float64{
	"Act":    1.0,
	"Attend": 0.7,
	"Track*": 0.4,
	"Track":  0.2,
}

// ArbiterAlert mirrors the threat-intel-arbiter Alert shape we consume.
type ArbiterAlert struct {
	ID         string   `json:"id"`
	Action     string   `json:"action"`
	Severity   string   `json:"severity"`
	CVEs       []string `json:"cves"`
	Techniques []string `json:"techniques"`
}

// ArbiterExport is the top-level JSON format from the arbiter.
type ArbiterExport struct {
	Alerts []ArbiterAlert `json:"alerts"`
}

// ArbiterFeed consumes threat-intel-arbiter output and yields priority-ordered
// TechniqueTasks. Each alert maps its techniques to tasks inheriting the alert's
// SSVC action priority.
type ArbiterFeed struct {
	Tasks []model.TechniqueTask
}

// Load reads an arbiter JSON export and populates the feed.
func (f *ArbiterFeed) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read arbiter export: %w", err)
	}
	var export ArbiterExport
	if err := json.Unmarshal(data, &export); err != nil {
		return fmt.Errorf("parse arbiter export: %w", err)
	}

	for _, alert := range export.Alerts {
		prio := actionPriority[alert.Action]
		if prio == 0 {
			prio = 0.1 // unknown action — lowest
		}
		sourceCVE := ""
		if len(alert.CVEs) > 0 {
			sourceCVE = alert.CVEs[0]
		}
		for _, tech := range alert.Techniques {
			f.Tasks = append(f.Tasks, model.TechniqueTask{
				TechniqueID: tech,
				SourceCVE:   sourceCVE,
				Priority:    prio,
			})
		}
	}

	// Sort by priority descending (highest first)
	sort.Slice(f.Tasks, func(i, j int) bool {
		return f.Tasks[i].Priority > f.Tasks[j].Priority
	})
	return nil
}

// Next returns all tasks in priority order.
func (f ArbiterFeed) Next(ctx context.Context) ([]model.TechniqueTask, error) {
	return f.Tasks, nil
}
