// Package collector pulls telemetry from the SIEM. WazuhCollector queries
// agent alerts from the Wazuh manager's alerts.json, filtered by host and
// time window. With an empty ManagerContainer it runs in dry mode.
package collector

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// WazuhCollector reads agent alerts from the manager's alerts.json log.
type WazuhCollector struct {
	BaseURL          string // e.g. https://localhost:55000 — empty => dry mode
	User             string
	Pass             string
	ManagerContainer string // docker container name, e.g. single-node-wazuh.manager-1

	// alertsPath overrides the source for testing; empty uses docker exec.
	alertsPath string
}

// Query returns Events from agent "host" within the given time window.
func (c *WazuhCollector) Query(ctx context.Context, w model.TimeWindow, host string) ([]model.Event, error) {
	if c.ManagerContainer == "" && c.alertsPath == "" {
		// dry mode
		raw, _ := json.Marshal(map[string]any{
			"agent": host, "rule": "synthetic", "note": "dry-run event",
		})
		return []model.Event{{ID: "dry-0001", Timestamp: time.Now().UTC(), Raw: raw}}, nil
	}

	lines, err := c.readAlerts(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("wazuh collector: %w", err)
	}

	var events []model.Event
	for _, line := range lines {
		var alert struct {
			ID        string          `json:"id"`
			Timestamp string          `json:"timestamp"`
			Raw       json.RawMessage `json:"-"`
		}
		if err := json.Unmarshal([]byte(line), &alert); err != nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, alert.Timestamp)
		if err != nil {
			// try without nanos
			ts, err = time.Parse("2006-01-02T15:04:05-0700", alert.Timestamp)
			if err != nil {
				continue
			}
		}
		if ts.Before(w.Start) || ts.After(w.End) {
			continue
		}
		events = append(events, model.Event{
			ID:        alert.ID,
			Timestamp: ts,
			Raw:       json.RawMessage(line),
		})
	}
	if events == nil {
		events = []model.Event{} // never nil
	}
	return events, nil
}

// readAlerts gets lines from alerts.json matching host, either via docker
// exec or from a local fixture file (test mode).
func (c *WazuhCollector) readAlerts(ctx context.Context, host string) ([]string, error) {
	if c.alertsPath != "" {
		return readAlertsFile(c.alertsPath, host)
	}
	cmd := exec.CommandContext(ctx, "docker", "exec", c.ManagerContainer,
		"grep", host, "/var/ossec/logs/alerts/alerts.json")
	out, err := cmd.Output()
	if err != nil {
		// grep returns 1 on no matches — that's not an error for us
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("docker exec grep: %w", err)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			lines = append(lines, t)
		}
	}
	return lines, nil
}

func readAlertsFile(path, host string) ([]string, error) {
	cmd := exec.Command("grep", host, path)
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("grep fixture: %w", err)
	}
	var lines []string
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			lines = append(lines, t)
		}
	}
	return lines, nil
}
