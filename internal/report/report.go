// Package report emits campaign output. JSONReporter prints indented JSON to
// stdout; HTMLReporter writes a self-contained HTML coverage grid.
package report

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"

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
