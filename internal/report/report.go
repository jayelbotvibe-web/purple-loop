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
.DETECTED{color:#4f4}.MISSED{color:#f44}.ERROR{color:#f0f}.NO_TELEMETRY{color:#fb0}.INCONCLUSIVE{color:#aaa}
.summary{display:flex;gap:1.5em;margin:1em 0}
.summary span{font-size:1.2em}
</style></head><body>
<h1>Purple Loop — Coverage Report</h1>
<p>` + html.EscapeString(run.StartedAt.Format("2006-01-02 15:04:05 UTC")) + `</p>`)

	// Trust banners — an operator must never mistake a synthetic or
	// canary-failed report for verified coverage.
	if run.Synthetic {
		f.WriteString(`<div style="background:#7f1d1d;color:#fff;padding:1em;border-radius:4px;margin:1em 0;font-weight:bold;text-align:center">⚠ SYNTHETIC / DRY-RUN PIPELINE — these results are NOT real telemetry and must not be used as evidence.</div>`)
	}
	if run.Inconclusive {
		f.WriteString(`<div style="background:#78350f;color:#fff;padding:1em;border-radius:4px;margin:1em 0;font-weight:bold;text-align:center">⚠ INCONCLUSIVE — the pipeline positive control (canary) did not fire; coverage is not valid.<br><span style="font-weight:normal">` + html.EscapeString(run.CanaryDetail) + `</span></div>`)
	}

	f.WriteString(`<div class="summary">`)

	for _, v := range []model.Verdict{model.Detected, model.Missed, model.NoTelemetry, model.Inconclusive, model.SkippedPrereq, model.Errored} {
		if n, ok := counts[v]; ok && n > 0 {
			f.WriteString(fmt.Sprintf(`<span class="%s">%s: %d</span>`, v, v, n))
		}
	}
	f.WriteString(`</div>
<div class="narrative"><strong>` + narrativeHeadline(counts) + `</strong></div>
<table><tr><th>Priority</th><th>CVE</th><th>Technique</th><th>Atomic</th><th>Verdict</th><th>Attribution</th><th>Latency</th><th>Events</th><th>Rule / why not</th></tr>`)

	for _, c := range run.Chains {
		evCount := fmt.Sprintf("%d", c.EventsCollected)
		prio := fmt.Sprintf("%.2f", c.ArbiterPriority)
		cve := orDash(c.SourceCVE)

		// The last column carries the rule that fired, or — when nothing did —
		// the reason, so a gap is never left unexplained.
		detail := c.RuleMatched
		if detail == "" {
			detail = orDash(c.Note)
		}

		// Provenance: a substituted command must not read as the upstream atomic.
		atomicCell := html.EscapeString(orDash(c.Atomic.ID))
		if c.Atomic.OverrideReason != "" {
			atomicCell += ` <span title="` + html.EscapeString(c.Atomic.OverrideReason) + `" style="color:#f59e0b">⚑</span>`
		}

		latency := "—"
		if c.DetectLatencyMS > 0 {
			latency = fmt.Sprintf("%.1fs", float64(c.DetectLatencyMS)/1000)
		}

		attr := string(c.Attribution)
		attrStyle := ""
		switch c.Attribution {
		case model.WindowOverlap:
			attrStyle = ` style="color:#f59e0b" title="another technique ran inside this collection window — a matching event may belong to either"`
		case model.Unscoped:
			attrStyle = ` style="color:#9ca3af"`
		}

		f.WriteString(fmt.Sprintf(
			`<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="%s">%s</td><td%s>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
			prio, html.EscapeString(cve), html.EscapeString(c.TechniqueID), atomicCell,
			c.Verdict, c.Verdict, attrStyle, html.EscapeString(orDash(attr)),
			latency, evCount, html.EscapeString(detail)))
	}

	f.WriteString("</table></body></html>")
	return nil
}

// narrativeHeadline reports coverage over the techniques that were actually
// exercised. A technique that ERRORed (unresolvable atomic, platform mismatch),
// was SKIPPED_PREREQ, or produced no telemetry never tested a detection, so
// counting any of them as "missed" would invent detection gaps out of
// harness failures — the same error class as presence-based coverage.
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func narrativeHeadline(counts map[model.Verdict]int) string {
	total := 0
	for _, n := range counts {
		total += n
	}
	if total == 0 {
		return "No techniques tested."
	}
	det := counts[model.Detected]
	miss := counts[model.Missed]
	notRun := counts[model.Errored] + counts[model.SkippedPrereq] + counts[model.NoTelemetry] + counts[model.Inconclusive]
	headline := fmt.Sprintf("%d of %d techniques exercised: %d detected / %d missed",
		det+miss, total, det, miss)
	if notRun > 0 {
		headline += fmt.Sprintf(" — %d not exercised (see per-technique notes)", notRun)
	}
	return headline
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
		Name        string            `json:"name"`
		Description string            `json:"description"`
		Domain      string            `json:"domain"`
		Versions    map[string]string `json:"versions"`
		Techniques  []navTechnique    `json:"techniques"`
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
		model.Detected:      {"#4caf50", 100},
		model.Missed:        {"#f44336", 0},
		model.Errored:       {"#e91e63", 0},
		model.SkippedPrereq: {"#9e9e9e", 0},
	}

	desc := fmt.Sprintf("Detection coverage from campaign run at %s", run.StartedAt.Format(time.RFC3339))
	if run.Synthetic {
		desc = "SYNTHETIC / DRY-RUN — NOT real telemetry. " + desc
	} else if run.Inconclusive {
		desc = "INCONCLUSIVE — canary did not fire, coverage not valid. " + desc
	}
	layer := navLayer{
		Name:        "Purple Loop Coverage",
		Description: desc,
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
