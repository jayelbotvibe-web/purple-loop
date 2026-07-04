// Package report emits campaign output. JSONReporter prints indented JSON to
// stdout; Phase 2 adds HTMLReporter and a Navigator-layer exporter.
package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

type JSONReporter struct {
	Out io.Writer
}

func (r JSONReporter) Write(run model.CampaignResult) error {
	enc := json.NewEncoder(r.Out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(run); err != nil {
		return fmt.Errorf("encode campaign: %w", err)
	}
	return nil
}
