// Package collector pulls telemetry from the SIEM. WazuhCollector queries
// agent alerts from the Wazuh manager's alerts.json, filtered by host and
// time window. With an empty ManagerContainer it runs in dry mode.
package collector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// timestampLayouts are tried in order when parsing Wazuh archive timestamps.
// Wazuh emits formats like "2026-07-04T10:37:28.086+0000" (ms + numeric offset
// without colon). Go's RFC3339Nano requires a colon in the offset, and the
// fallback layout without fractional seconds relies on lenient parsing.
// An explicit ordered list removes the fragility.
var timestampLayouts = []string{
	time.RFC3339Nano,               // "2006-01-02T15:04:05.999999999Z07:00"
	"2006-01-02T15:04:05.000-0700", // ms + numeric offset
	"2006-01-02T15:04:05-0700",     // no fraction + numeric offset
}

// parseTimestamp tries each known layout and returns the first successful parse.
func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range timestampLayouts {
		t, err := time.Parse(layout, s)
		if err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse timestamp %q", s)
}

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
			"Image":       "/usr/bin/id",
			"ParentImage": "/bin/bash",
			"CommandLine": "id",
			"User":        "root",
			"note":        "dry-run event (matches proc_creation_susp_shell)",
		})
		return []model.Event{{ID: "dry-0001", Timestamp: time.Now().UTC(), Raw: raw}}, nil
	}

	lines, err := c.readAlerts(ctx, host, w)
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
		ts, err := parseTimestamp(alert.Timestamp)
		if err != nil {
			continue
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

const archivesPath = "/var/ossec/logs/archives/archives.json"

// readAlerts gets lines from alerts.json matching host, either via docker
// exec or from a local fixture file (test mode). For the docker path it adds a
// coarse date pre-filter derived from the window, so a single query only reads
// the day(s) it actually spans instead of the entire archive history.
func (c *WazuhCollector) readAlerts(ctx context.Context, host string, w model.TimeWindow) ([]string, error) {
	if c.alertsPath != "" {
		return runGrep(exec.Command("grep", "-F", "--", host, c.alertsPath))
	}

	dateRe := dateAlternation(w)
	var cmd *exec.Cmd
	if dateRe == "" {
		cmd = exec.CommandContext(ctx, "docker", "exec", c.ManagerContainer,
			"grep", "-F", "--", host, archivesPath)
	} else {
		pipeline := fmt.Sprintf("grep -F -- %s %s | grep -E -- %s",
			shQuote(host), shQuote(archivesPath), shQuote(dateRe))
		cmd = exec.CommandContext(ctx, "docker", "exec", c.ManagerContainer, "sh", "-c", pipeline)
	}
	return runGrep(cmd)
}

// runGrep executes a grep command, treating exit status 1 (no matches) as an
// empty result rather than an error, and scans the output into lines.
func runGrep(cmd *exec.Cmd) ([]string, error) {
	out, err := cmd.Output()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return nil, nil
		}
		return nil, fmt.Errorf("grep: %w", err)
	}
	return scanLines(out), nil
}

// scanLines splits grep output into trimmed, non-empty lines. The buffer is
// enlarged because a single Wazuh archive event can exceed bufio's default
// 64 KB token limit, which would otherwise silently drop long events.
func scanLines(out []byte) []string {
	var lines []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if t := strings.TrimSpace(sc.Text()); t != "" {
			lines = append(lines, t)
		}
	}
	return lines
}

// dateAlternation builds a grep -E alternation of the YYYY-MM-DD stamps the
// window spans (e.g. "2026-07-04|2026-07-05"). Returns "" to skip the
// pre-filter when the window is unset or spans an implausibly large range.
func dateAlternation(w model.TimeWindow) string {
	if w.Start.IsZero() || w.End.IsZero() || w.End.Before(w.Start) {
		return ""
	}
	const maxDays = 31
	start := w.Start.UTC().Truncate(24 * time.Hour)
	end := w.End.UTC().Truncate(24 * time.Hour)
	var stamps []string
	for d := start; !d.After(end); d = d.Add(24 * time.Hour) {
		stamps = append(stamps, d.Format("2006-01-02"))
		if len(stamps) > maxDays {
			return "" // range too wide to be a useful pre-filter
		}
	}
	return strings.Join(stamps, "|")
}

// shQuote single-quotes a string for safe use inside an sh -c command.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
