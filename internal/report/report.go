// Package report emits campaign output. JSONReporter prints indented JSON to
// stdout; HTMLReporter writes a self-contained HTML coverage grid.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// JSONReporter prints indented JSON to an io.Writer.
type JSONReporter struct {
	Out io.Writer
}

func (r JSONReporter) Write(run model.CampaignResult) error {
	if r.Out == nil {
		r.Out = os.Stdout
	}
	enc := json.NewEncoder(r.Out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(run); err != nil {
		return fmt.Errorf("encode campaign: %w", err)
	}
	return nil
}

// HTMLReporter writes a self-contained HTML coverage report to a file.
type HTMLReporter struct {
	Path string
}

func (r HTMLReporter) Write(run model.CampaignResult) error {
	f, err := os.Create(r.Path)
	if err != nil {
		return fmt.Errorf("create report: %w", err)
	}
	defer f.Close()

	counts := map[model.Verdict]int{}
	for _, c := range run.Chains {
		counts[c.Verdict]++
	}

	f.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"><title>Purple Loop Coverage</title>
<style>body{font-family:system-ui,sans-serif;max-width:900px;margin:2em auto;padding:0 1em;background:#111;color:#ddd}
h1{color:#fff}table{width:100%;border-collapse:collapse;margin-top:1em}
th,td{padding:.5em .75em;text-align:left;border-bottom:1px solid #333}
th{background:#1a1a2e;color:#ccc}
tr:hover{background:#1a1a2e}
.DETECTED{color:#4f4}.PARTIAL{color:#fa0}.MISSED{color:#f44}.ERROR{color:#f0f}
.summary{display:flex;gap:1.5em;margin:1em 0}
.summary span{font-size:1.2em}
</style></head><body>
<h1>Purple Loop — Coverage Report</h1>
<p>` + html.EscapeString(run.StartedAt.Format("2006-01-02 15:04:05 UTC")) + `</p>
<div class="summary">`)

	for _, v := range []model.Verdict{model.Detected, model.Partial, model.Missed, model.Errored} {
		if n, ok := counts[v]; ok && n > 0 {
			f.WriteString(fmt.Sprintf(`<span class="%s">%s: %d</span>`, v, v, n))
		}
	}
	f.WriteString(`</div><table><tr><th>Technique</th><th>Verdict</th><th>Events</th><th>Rule</th><th>Evidence</th></tr>`)

	for _, c := range run.Chains {
		evCount := fmt.Sprintf("%d", c.EventsCollected)
		rule := c.RuleMatched
		if rule == "" {
			rule = "—"
		}
		evidence := "—"
		if len(c.Evidence) > 0 {
			evidence = fmt.Sprintf("%d event(s)", len(c.Evidence))
		}
		f.WriteString(fmt.Sprintf(`<tr><td>%s</td><td class="%s">%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			html.EscapeString(c.TechniqueID), c.Verdict, c.Verdict,
			evCount, html.EscapeString(rule), evidence))
	}

	f.WriteString("</table></body></html>")
	return nil
}

// NavigatorLayerReporter writes an ATT&CK Navigator layer JSON file.
type NavigatorLayerReporter struct {
	Path string
}

func (r NavigatorLayerReporter) Write(run model.CampaignResult) error {
	type navTechnique struct {
		TechniqueID string `json:"techniqueID"`
		Score       int    `json:"score"`
		Color       string `json:"color"`
		Comment     string `json:"comment,omitempty"`
	}
	type navLayer struct {
		Name        string         `json:"name"`
		Description string         `json:"description"`
		Domain      string         `json:"domain"`
		Versions    map[string]string `json:"versions"`
		Techniques  []navTechnique `json:"techniques"`
		Gradient    struct {
			Colors []string `json:"colors"`
			MinVal int      `json:"minValue"`
			MaxVal int      `json:"maxValue"`
		} `json:"gradient"`
	}

	verdictColors := map[model.Verdict]struct {
		color string
		score int
	}{
		model.Detected: {"#4caf50", 100},
		model.Partial:  {"#ff9800", 50},
		model.Missed:   {"#f44336", 0},
		model.Errored:  {"#e91e63", 0},
	}

	layer := navLayer{
		Name:        "Purple Loop Coverage",
		Description: fmt.Sprintf("Detection coverage from campaign run at %s", run.StartedAt.Format(time.RFC3339)),
		Domain:      "mitre-enterprise",
		Versions:    map[string]string{"layer": "4.5", "attack": "16"},
	}
	layer.Gradient.Colors = []string{"#f44336", "#ff9800", "#4caf50"}
	layer.Gradient.MinVal = 0
	layer.Gradient.MaxVal = 100

	for _, c := range run.Chains {
		vc := verdictColors[c.Verdict]
		layer.Techniques = append(layer.Techniques, navTechnique{
			TechniqueID: c.TechniqueID,
			Score:       vc.score,
			Color:       vc.color,
			Comment:     fmt.Sprintf("%s: %d events, rule %s", c.Verdict, c.EventsCollected, c.RuleMatched),
		})
	}

	f, err := os.Create(r.Path)
	if err != nil {
		return fmt.Errorf("create navigator layer: %w", err)
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(layer)
}
