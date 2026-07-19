// Package server provides the read-only web UI and JSON API for purpleloop serve.
package server

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed web
var webFS embed.FS

var idRe = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// New returns an http.Handler serving the embedded dashboard and a read-only
// JSON API over the given reports directory.
func New(reportsDir string) http.Handler {
	mux := http.NewServeMux()

	// Embedded dashboard
	web, _ := fs.Sub(webFS, "web")
	mux.Handle("/", http.FileServer(http.FS(web)))

	// API — read-only, only GET
	mux.Handle("/api/health", get(func(w http.ResponseWriter, r *http.Request) {
		health(w, reportsDir)
	}))
	mux.Handle("/api/runs", get(func(w http.ResponseWriter, r *http.Request) {
		runs(w, r, reportsDir)
	}))
	mux.Handle("/api/runs/latest", get(func(w http.ResponseWriter, r *http.Request) {
		latest(w, reportsDir)
	}))
	mux.Handle("/api/runs/", get(func(w http.ResponseWriter, r *http.Request) {
		runDetail(w, r, reportsDir)
	}))
	mux.Handle("/api/history", get(func(w http.ResponseWriter, r *http.Request) {
		history(w, reportsDir)
	}))

	return mux
}

// get wraps a handler to accept only GET; returns 405 otherwise.
func get(fn http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusMethodNotAllowed)
			w.Write([]byte(`{"error":"read-only — only GET allowed"}`))
			return
		}
		fn(w, r)
	})
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func jsonErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// health returns a status check.
func health(w http.ResponseWriter, reportsDir string) {
	n, _ := countRuns(reportsDir)
	jsonOK(w, map[string]any{"status": "ok", "runs": n})
}

// runs lists all runs, newest first.
func runs(w http.ResponseWriter, r *http.Request, reportsDir string) {
	ids, err := listRunIDs(reportsDir)
	if err != nil {
		jsonErr(w, 500, "failed to list runs")
		return
	}
	type summary struct {
		ID           string `json:"id"`
		Campaign     string `json:"campaign"`
		GeneratedAt  string `json:"generated_at"`
		CoveragePct  int    `json:"coverage_pct"`
		CanaryHealth bool   `json:"canary_healthy"`
	}
	var out []summary
	for _, id := range ids {
		// #nosec G304 — id validated by idRe (no path separators)
		raw, err := os.ReadFile(filepath.Join(reportsDir, "runs", id, "coverage.json"))
		if err != nil {
			continue
		}
		var d map[string]any
		if json.Unmarshal(raw, &d) != nil {
			continue
		}
		s, ok := d["summary"].(map[string]any)
		if !ok {
			continue // malformed run — skip
		}
		c, ok := d["canary"].(map[string]any)
		if !ok {
			continue
		}
		out = append(out, summary{
			ID:           id,
			Campaign:     str(d["campaign"]),
			GeneratedAt:  str(d["generated_at"]),
			CoveragePct:  int(num(s["coverage_pct"])),
			CanaryHealth: boolVal(c["healthy"]),
		})
	}
	jsonOK(w, out)
}

// latest returns the full coverage.json of the newest run.
func latest(w http.ResponseWriter, reportsDir string) {
	ids, _ := listRunIDs(reportsDir)
	if len(ids) == 0 {
		jsonErr(w, 404, "no runs yet")
		return
	}
	serveRun(w, reportsDir, ids[0])
}

// runDetail returns full coverage.json for a specific run.
func runDetail(w http.ResponseWriter, r *http.Request, reportsDir string) {
	id := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	if id == "latest" {
		return // handled by /api/runs/latest
	}
	if !idRe.MatchString(id) {
		jsonErr(w, 400, "invalid run id")
		return
	}
	serveRun(w, reportsDir, id)
}

// history returns the trend array.
func history(w http.ResponseWriter, reportsDir string) {
	// #nosec G304 — static path, no user input
	raw, err := os.ReadFile(filepath.Join(reportsDir, "history.json"))
	if err != nil {
		jsonOK(w, []any{})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func serveRun(w http.ResponseWriter, reportsDir, id string) {
	// #nosec G304 — id validated by idRe (no path separators)
	raw, err := os.ReadFile(filepath.Join(reportsDir, "runs", id, "coverage.json"))
	if err != nil {
		jsonErr(w, 404, "run not found")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(raw)
}

func listRunIDs(reportsDir string) ([]string, error) {
	d := filepath.Join(reportsDir, "runs")
	entries, err := os.ReadDir(d)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() && idRe.MatchString(e.Name()) {
			ids = append(ids, e.Name())
		}
	}
	// Sort newest first by reversing the slice
	for i := 0; i < len(ids)/2; i++ {
		ids[i], ids[len(ids)-1-i] = ids[len(ids)-1-i], ids[i]
	}
	return ids, nil
}

func countRuns(reportsDir string) (int, error) {
	ids, err := listRunIDs(reportsDir)
	if err != nil {
		return 0, err
	}
	return len(ids), nil
}

// Helper type casts
func str(v any) string {
	s, _ := v.(string)
	return s
}
func num(v any) float64 {
	n, _ := v.(float64)
	return n
}
func boolVal(v any) bool {
	b, _ := v.(bool)
	return b
}

// suppress unused log import
func init() { _ = log.Flags }
