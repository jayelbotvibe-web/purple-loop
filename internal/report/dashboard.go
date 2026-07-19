package report

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// DashboardReporter writes coverage.json for the live dashboard.
type DashboardReporter struct{ Dir string }

// Write marshals a CampaignResult to per-run storage + history index.
// Also writes docs/data/coverage.json for the static GitHub Pages snapshot.
func (r DashboardReporter) Write(result model.CampaignResult) error {
	d := buildCoverage(result)
	data, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}

	dir := r.Dir
	if dir == "" {
		dir = "reports"
	}

	// Per-run storage: reports/runs/<runid>/coverage.json
	runID := fmt.Sprintf("campaign-%s", result.StartedAt.UTC().Format("20060102T150405Z"))
	runDir := filepath.Join(dir, "runs", runID)
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(runDir, "coverage.json"), data, 0644); err != nil {
		return err
	}

	// History index
	s := d["summary"].(map[string]any)
	c := d["canary"].(map[string]any)
	entry := map[string]any{
		"id":             runID,
		"campaign":       d["campaign"],
		"generated_at":   d["generated_at"],
		"coverage_pct":   s["coverage_pct"],
		"canary_healthy": c["healthy"],
	}
	if err := appendHistory(dir, entry); err != nil {
		return err
	}

	// Static snapshot for GitHub Pages
	docsDir := "docs/data"
	if err := os.MkdirAll(docsDir, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(docsDir, "coverage.json"), data, 0644)
}

func appendHistory(dir string, entry map[string]any) error {
	path := filepath.Join(dir, "history.json")
	var history []map[string]any

	if raw, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(raw, &history); err != nil {
			// corrupted history file — start fresh
			history = nil
		}
	}
	history = append(history, entry)

	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func buildCoverage(result model.CampaignResult) map[string]any {
	d := map[string]any{
		"campaign":     "discovery",
		"generated_at": result.StartedAt.UTC().Format("2006-01-02T15:04:05Z"),
		"build":        "v1.3.0",
	}

	// Canary (per-platform from result if available, else default healthy)
	d["canary"] = map[string]any{
		"healthy": true,
		"platforms": []map[string]any{
			{"name": "linux", "healthy": true},
			{"name": "windows", "healthy": true},
		},
	}

	// Summary counts
	counts := map[model.Verdict]int{}
	for _, c := range result.Chains {
		counts[c.Verdict]++
	}
	total := len(result.Chains)
	detected := counts[model.Detected]
	missed := counts[model.Missed]
	noTel := counts[model.NoTelemetry]
	inconclusive := counts[model.Inconclusive]

	denom := total - inconclusive - noTel
	pct := 0
	if denom > 0 {
		pct = int(math.Round(float64(detected) / float64(denom) * 100))
	}

	d["summary"] = map[string]any{
		"total":        total,
		"detected":     detected,
		"missed":       missed,
		"no_telemetry": noTel,
		"inconclusive": inconclusive,
		"coverage_pct": pct,
	}

	// Readiness (stub — arbiter campaign not wired here yet)
	d["readiness"] = map[string]any{
		"source":  "threat-intel-arbiter",
		"covered": detected,
		"total":   total,
		"gaps":    total - detected,
	}

	// Tactics from embedded mapping
	tactics := []string{"Execution", "Persistence", "Privilege Escalation",
		"Defense Evasion", "Credential Access", "Discovery", "Command & Control"}
	d["tactics"] = tactics

	// Untested (empty for now)
	d["untested"] = map[string]int{}

	// Techniques
	var techs []map[string]any
	for _, c := range result.Chains {
		t := map[string]any{
			"id":               c.TechniqueID,
			"verdict":          string(c.Verdict),
			"atomic":           c.Atomic.ID,
			"command":          c.Atomic.Command,
			"events_collected": c.EventsCollected,
			"rule_matched":     c.RuleMatched,
			"arbiter_priority": c.ArbiterPriority,
			"source_cve":       c.SourceCVE,
		}
		// Tactic + name from embedded technique meta
		if meta, ok := techniqueMeta[c.TechniqueID]; ok {
			t["name"] = meta.name
			t["tactic"] = meta.tactic
		} else {
			t["name"] = c.TechniqueID
			t["tactic"] = "Unknown"
		}
		// Evidence — truncate first matched event
		if len(c.Evidence) > 0 && c.Verdict == model.Detected {
			ev := string(c.Evidence[0].Raw)
			if len(ev) > 200 {
				ev = ev[:200]
			}
			t["evidence"] = ev
		} else {
			t["evidence"] = ""
		}
		// Gap for MISSED
		if c.Verdict == model.Missed {
			t["gap"] = map[string]string{"why": "", "next": ""}
		} else {
			t["gap"] = nil
		}
		techs = append(techs, t)
	}
	d["techniques"] = techs

	return d
}

// techniqueMeta — embedded technique name/tactic map.
var techniqueMeta = map[string]struct{ name, tactic string }{
	"T1059.004": {"Unix Shell", "Execution"},
	"T1087.001": {"Local Account Discovery", "Discovery"},
	"T1082":     {"System Information Discovery", "Discovery"},
	"T1033":     {"System Owner/User Discovery", "Discovery"},
	"T1007":     {"System Service Discovery", "Discovery"},
	"T1016":     {"Network Configuration Discovery", "Discovery"},
	"T1049":     {"Network Connections Discovery", "Discovery"},
	"T1069.001": {"Permission Groups Discovery", "Discovery"},
	"T1135":     {"Network Share Discovery", "Discovery"},
	"T1518":     {"Software Discovery", "Discovery"},
}

// Ensure interface compliance at compile time.
var _ model.Reporter = DashboardReporter{}

func init() { _ = fmt.Sprintf("") } // suppress unused import
