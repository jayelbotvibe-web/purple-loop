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
	Missed       Verdict = "MISSED"
	NoTelemetry  Verdict = "NO_TELEMETRY"
	Inconclusive Verdict = "INCONCLUSIVE"
	Errored      Verdict = "ERROR"

	// SkippedPrereq means the atomic's own prerequisites were not met, so it
	// never ran. That is not a detection gap and must never be counted as one —
	// the same class of error as crediting a low-fidelity event as evidence.
	SkippedPrereq Verdict = "SKIPPED_PREREQ"
)

// Attribution states how tightly a verdict is bound to the execution that
// claims it. A DETECTED whose window overlapped another technique's run is not
// the same quality of evidence as one that did not, and a report that does not
// say so overstates its own rigour.
type Attribution string

const (
	// WindowAndHostScoped is the strongest: the telemetry query was bounded to
	// this execution's window AND filtered to this target host.
	WindowAndHostScoped Attribution = "window_and_host_scoped"
	// WindowScoped means time-bounded, but the host was not resolved.
	WindowScoped Attribution = "window_scoped"
	// WindowOverlap means another technique in this campaign ran inside this
	// one's collection window, so a matching event may belong to either.
	WindowOverlap Attribution = "window_overlap"
	// Unscoped means the verdict cannot be attributed — a synthetic pipeline.
	Unscoped Attribution = "unscoped"
)

// TimeWindow bounds a telemetry query to an execution's real time span.
type TimeWindow struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// Overlaps reports whether two collection windows intersect. Two techniques
// whose windows overlap can each collect the other's events.
func (w TimeWindow) Overlaps(o TimeWindow) bool {
	return w.Start.Before(o.End) && o.Start.Before(w.End)
}

// Target is a host inside the isolated lab network. Attacks NEVER target
// anything outside the lab (see AGENT_PLAYBOOK.md, Lab containment).
type Target struct {
	Host string // e.g. "victim01"
	Kind string // "linux" | "windows"
}

// AtomicTest is a single Atomic Red Team test mapped to an ATT&CK technique.
//
// Name/GUID/Source exist so a report can prove WHICH upstream atomic produced a
// command. Source is "atomic-red-team" for a vendored test and "override" for a
// lab substitution, in which case OverrideReason says why — a substituted
// command must never read as the upstream atomic.
type AtomicTest struct {
	ID             string `json:"id"`
	TechniqueID    string `json:"technique_id"`
	Name           string `json:"name,omitempty"`
	GUID           string `json:"guid,omitempty"`
	Command        string `json:"command"`
	CleanupCommand string `json:"cleanup_command,omitempty"`
	Executor       string `json:"executor"`
	Source         string `json:"source,omitempty"`
	OverrideReason string `json:"override_reason,omitempty"`
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

// Window returns the execution's time span, padded only on the END so the SIEM
// has room to ingest the resulting events. The start is NOT padded backward:
// widening it into the past can capture an earlier run's matching events and
// credit them to this execution (false DETECTED). A small epsilon absorbs
// minor clock skew without reaching a prior test.
func (r RunResult) Window(pad time.Duration) TimeWindow {
	return TimeWindow{Start: r.StartedAt.Add(-2 * time.Second), End: r.FinishedAt.Add(pad)}
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

	// Note carries the reason behind a non-coverage verdict — why a technique
	// ERRORed, which prerequisite was unmet, which platform mismatched. An
	// unexplained gap is not actionable.
	Note string `json:"note,omitempty"`

	// RulesExpected lists every rule that should have fired; RulesMatched lists
	// those that did. RuleMatched above stays as the first match, preserving the
	// documented proof-chain shape.
	RulesExpected []string `json:"rules_expected,omitempty"`
	RulesMatched  []string `json:"rules_matched,omitempty"`

	// Attribution states how tightly this verdict is bound to its execution.
	Attribution Attribution `json:"attribution,omitempty"`

	// Window is the telemetry query span, kept so overlapping executions can be
	// detected across the campaign.
	Window TimeWindow `json:"window"`

	// DetectLatencyMS is the gap between execution start and the earliest
	// matching event. Zero when nothing matched.
	DetectLatencyMS int64 `json:"detect_latency_ms,omitempty"`

	// Collected is every event the query returned, not just the matching ones.
	// It is excluded from the proof-chain JSON (that contract carries evidence,
	// which is the matching subset) and exists so a run can be captured and
	// replayed against future rule changes.
	Collected []Event `json:"-"`
}

// CampaignResult aggregates every technique validated in one run.
//
// The three trust fields enforce the hard contracts in code (not just docs):
//   - Synthetic: any pipeline stage was dry/synthetic, so the chains are NOT
//     real telemetry and must never be presented or published as evidence.
//   - CanaryHealthy / Inconclusive: the pipeline positive control. On a real
//     run, if the canary did not fire the run is INCONCLUSIVE and its coverage
//     must not be treated as valid.
type CampaignResult struct {
	StartedAt     time.Time    `json:"started_at"`
	Chains        []ProofChain `json:"chains"`
	Synthetic     bool         `json:"synthetic"`               // dry/synthetic pipeline — not real evidence
	CanaryHealthy bool         `json:"canary_healthy"`          // positive control fired (real runs)
	Inconclusive  bool         `json:"inconclusive"`            // canary failed on a real run → coverage invalid
	CanaryDetail  string       `json:"canary_detail,omitempty"` // why the canary failed

	// Campaign names the plan that ran; AtomicsCommit records the vendored
	// Atomic Red Team revision, so a report states exactly which upstream
	// commands produced it.
	Campaign      string `json:"campaign,omitempty"`
	AtomicsCommit string `json:"atomics_commit,omitempty"`

	// UntestedRules names detections this campaign did not exercise, with the
	// reason. An honest denominator needs the rules that were never tried, not
	// only the ones that were.
	UntestedRules map[string]string `json:"untested_rules,omitempty"`
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
