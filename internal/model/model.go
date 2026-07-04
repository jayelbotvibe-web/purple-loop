// Package model holds the shared types and the interfaces that form the
// seams of the engine. Every plane (intel, execution, telemetry) talks to
// the orchestrator through these interfaces so implementations stay swappable.
package model

import (
	"context"
	"encoding/json"
	"time"
)

// Verdict is the outcome of validating one technique's detection.
type Verdict string

const (
	Detected     Verdict = "DETECTED"
	Partial      Verdict = "PARTIAL"
	Missed       Verdict = "MISSED"
	NoTelemetry  Verdict = "NO_TELEMETRY"
	Inconclusive Verdict = "INCONCLUSIVE"
	Errored      Verdict = "ERROR"
)

// TimeWindow bounds a telemetry query to an execution's real time span.
type TimeWindow struct {
	Start time.Time
	End   time.Time
}

// Target is a host inside the isolated lab network. Attacks NEVER target
// anything outside the lab (see AGENT_PLAYBOOK.md, Lab containment).
type Target struct {
	Host string // e.g. "victim01"
	Kind string // "linux" | "windows"
}

// AtomicTest is a single Atomic Red Team test mapped to an ATT&CK technique.
type AtomicTest struct {
	ID             string `json:"id"`
	TechniqueID    string `json:"technique_id"`
	Command        string `json:"command"`
	CleanupCommand string `json:"cleanup_command,omitempty"`
	Executor       string `json:"executor"`
}

// RunResult is what the Executor records about one atomic execution.
type RunResult struct {
	Command    string    `json:"command"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   int       `json:"exit_code"`
	Stdout     string    `json:"-"`
	Stderr     string    `json:"-"`
}

// Window returns the execution's time span, padded so the SIEM has room to
// have ingested the resulting events.
func (r RunResult) Window(pad time.Duration) TimeWindow {
	return TimeWindow{Start: r.StartedAt.Add(-pad), End: r.FinishedAt.Add(pad)}
}

// Event is one normalised telemetry record pulled from the SIEM.
type Event struct {
	ID        string          `json:"event_id"`
	Timestamp time.Time       `json:"timestamp"`
	Raw       json.RawMessage `json:"raw"`
}

// TechniqueTask is one unit of work from a PriorityFeed.
type TechniqueTask struct {
	TechniqueID string   `json:"technique_id"`
	SourceCVE   string   `json:"source_cve,omitempty"`
	Priority    float64  `json:"priority"`
	AtomicIDs   []string `json:"atomic_ids"`
}

// SigmaRule is a minimal handle to a detection rule on disk.
type SigmaRule struct {
	Path  string `json:"path"`
	Title string `json:"title"`
}

// ProofChain is the evidence-backed result for one technique. Its JSON shape
// is the contract shown in DESIGN.md, section "The proof chain".
type ProofChain struct {
	TechniqueID     string     `json:"technique_id"`
	SourceCVE       string     `json:"source_cve,omitempty"`
	ArbiterPriority float64    `json:"arbiter_priority"`
	Atomic          AtomicTest `json:"atomic"`
	ExecutedAt      time.Time  `json:"executed_at"`
	EventsCollected int        `json:"events_collected"`
	RuleMatched     string     `json:"rule_matched"`
	Verdict         Verdict    `json:"verdict"`
	Evidence        []Event    `json:"evidence"`
}

// CampaignResult aggregates every technique validated in one run.
type CampaignResult struct {
	StartedAt time.Time    `json:"started_at"`
	Chains    []ProofChain `json:"chains"`
}

// ---- interfaces: the swappable seams of the system ----

// PriorityFeed yields technique tasks in the order they should be validated.
type PriorityFeed interface {
	Next(ctx context.Context) ([]TechniqueTask, error)
}

// Executor runs an atomic on a target and always cleans up afterwards.
type Executor interface {
	Run(ctx context.Context, test AtomicTest, target Target) (RunResult, error)
	Cleanup(ctx context.Context, test AtomicTest, target Target) error
}

// Collector pulls telemetry from whatever SIEM is deployed.
type Collector interface {
	Query(ctx context.Context, window TimeWindow, host string) ([]Event, error)
}

// Evaluator decides whether the collected events satisfy a detection.
type Evaluator interface {
	Evaluate(rule SigmaRule, events []Event) (Verdict, []Event, error)
}

// Reporter emits campaign output (stdout JSON, HTML, Navigator layer).
type Reporter interface {
	Write(run CampaignResult) error
}
