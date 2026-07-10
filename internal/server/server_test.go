package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestRuns_SkipsMalformedRun(t *testing.T) {
	dir := t.TempDir()

	// Create a valid run
	validDir := filepath.Join(dir, "runs", "valid-run")
	os.MkdirAll(validDir, 0755)
	good := map[string]any{
		"campaign":     "test",
		"generated_at": "2025-01-01T00:00:00Z",
		"summary": map[string]any{
			"coverage_pct": float64(50),
		},
		"canary": map[string]any{
			"healthy": true,
		},
	}
	goodJSON, _ := json.MarshalIndent(good, "", "  ")
	os.WriteFile(filepath.Join(validDir, "coverage.json"), goodJSON, 0644)

	// Create a malformed run (missing summary key)
	badDir := filepath.Join(dir, "runs", "bad-run")
	os.MkdirAll(badDir, 0755)
	bad := map[string]any{
		"campaign":     "test",
		"generated_at": "2025-01-01T00:00:00Z",
		// "summary" key intentionally omitted
		"canary": map[string]any{
			"healthy": true,
		},
	}
	badJSON, _ := json.MarshalIndent(bad, "", "  ")
	os.WriteFile(filepath.Join(badDir, "coverage.json"), badJSON, 0644)

	handler := New(dir)

	req := httptest.NewRequest("GET", "/api/runs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}

	var out []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Should have only the valid run; bad-run is skipped
	if len(out) != 1 {
		t.Fatalf("expected 1 run (bad skipped), got %d: %v", len(out), out)
	}

	if out[0]["id"] != "valid-run" {
		t.Fatalf("expected valid-run, got %v", out[0]["id"])
	}
}

func TestRuns_EmptyReportsDir(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "runs"), 0755)
	handler := New(dir)

	req := httptest.NewRequest("GET", "/api/runs", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rec.Code)
	}

	var out []map[string]any
	json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out) != 0 {
		t.Fatalf("expected empty list, got %v", out)
	}
}
