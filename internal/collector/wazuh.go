// Package collector pulls telemetry from the SIEM. WazuhCollector is a skeleton
// for the Wazuh REST API; with an empty BaseURL it runs in dry mode and returns
// one synthetic event so the pipeline is testable without a live lab.
package collector

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

type WazuhCollector struct {
	BaseURL string // e.g. https://localhost:55000 ; empty => dry mode
	User    string
	Pass    string
}

func (c WazuhCollector) Query(ctx context.Context, w model.TimeWindow, host string) ([]model.Event, error) {
	if c.BaseURL == "" {
		raw, _ := json.Marshal(map[string]any{
			"agent": host, "rule": "synthetic", "note": "dry-run event",
		})
		return []model.Event{{ID: "dry-0001", Timestamp: time.Now().UTC(), Raw: raw}}, nil
	}
	// Phase 1:
	//   1. POST /security/user/authenticate (basic auth) -> JWT
	//   2. GET alerts within [w.Start, w.End] for `host`
	//   3. normalise hits into []model.Event
	return nil, nil
}
