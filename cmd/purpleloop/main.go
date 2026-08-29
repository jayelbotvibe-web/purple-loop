// Command purpleloop is the CLI entrypoint. Uses stdlib flag to keep
// dependencies at zero.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/atomic"
	"github.com/jayelbotvibe-web/purple-loop/internal/canary"
	"github.com/jayelbotvibe-web/purple-loop/internal/capture"
	"github.com/jayelbotvibe-web/purple-loop/internal/collector"
	"github.com/jayelbotvibe-web/purple-loop/internal/evaluator"
	"github.com/jayelbotvibe-web/purple-loop/internal/executor"
	"github.com/jayelbotvibe-web/purple-loop/internal/feed"
	"github.com/jayelbotvibe-web/purple-loop/internal/lab"
	"github.com/jayelbotvibe-web/purple-loop/internal/mapping"
	"github.com/jayelbotvibe-web/purple-loop/internal/model"
	"github.com/jayelbotvibe-web/purple-loop/internal/report"
	"github.com/jayelbotvibe-web/purple-loop/internal/server"
)

// Default locations for the vendored Atomic Red Team tree and the lab
// overrides that sit in front of it.
const (
	defaultAtomicsRoot  = "lab/atomic-red-team"
	defaultOverrides    = "mappings/atomic-overrides.yml"
	defaultRuleMap      = "mappings/attack_rule_map.json"
	defaultTargets      = "lab/targets.yml"
	atomicsCommitRecord = "mappings/atomic-red-team.commit"

	// collectWindow is how far past the execution the collector looks. Phase 3
	// replaces this with a poll bounded by the ingestion watermark.
	collectWindow = 10 * time.Minute
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: purpleloop run|replay|precision|diff|canary|serve [...]")
		os.Exit(1)
	}

	if os.Args[1] == "canary" {
		runCanaryCmd()
		return
	}

	if os.Args[1] == "serve" {
		runServe()
		return
	}

	if os.Args[1] == "replay" {
		runReplay()
		return
	}

	if os.Args[1] == "precision" {
		runPrecision()
		return
	}

	if os.Args[1] == "diff" {
		runDiff()
		return
	}

	if os.Args[1] != "run" {
		fmt.Fprintln(os.Stderr, "usage: purpleloop run [--technique <ID> | --plan <file>] [flags]")
		os.Exit(2)
	}
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	technique := fs.String("technique", "", "Single technique ID, e.g. T1059.004")
	planFile := fs.String("plan", "", "YAML plan file (e.g. plans/discovery.yml)")
	arbiterFile := fs.String("arbiter", "", "Arbiter JSON export (threat-intel-arbiter output)")
	emulationFile := fs.String("emulation", "", "Multi-stage emulation plan (e.g. emulation/discovery-chain.yml)")
	output := fs.String("output", "", "Output file (.html for coverage report, empty = JSON stdout)")
	dryRun := fs.Bool("dry-run", false, "run the pipeline without a live lab")
	victim := fs.String("victim-container", "", "Docker container for execution (e.g. purpleloop-victim)")
	manager := fs.String("manager-container", "", "Docker container for Wazuh manager")
	atomicsRoot := fs.String("atomics", defaultAtomicsRoot, "vendored Atomic Red Team checkout")
	ruleMapPath := fs.String("rule-map", defaultRuleMap, "technique -> atomic -> expected rules mapping")
	targetsPath := fs.String("targets", defaultTargets, "lab target inventory")
	settleTimeout := fs.Duration("settle-timeout", 60*time.Second,
		"how long to wait for an execution's telemetry before calling it NO_TELEMETRY. "+
			"Must exceed the victim's collection interval: Wazuh <localfile> command monitoring "+
			"defaults to 360s, so a 60s budget can never see it")
	settlePoll := fs.Duration("settle-poll", 3*time.Second, "gap between telemetry polls")
	overridesPath := fs.String("overrides", defaultOverrides, "lab overrides for unusable atomics")
	_ = fs.Parse(os.Args[2:])

	ctx := context.Background()

	// A partial container config would fire a REAL atomic on the victim while
	// collecting from a dry (synthetic) SIEM — a real attack paired with a
	// fabricated event. Reject it: a real run needs both, or pass --dry-run.
	if !*dryRun && (*victim == "") != (*manager == "") {
		fmt.Fprintln(os.Stderr, "error: a real run needs BOTH --victim-container and --manager-container (or pass --dry-run)")
		os.Exit(2)
	}

	// Warn loudly whenever any pipeline stage is synthetic, so a dry-run report
	// can never be mistaken for real detection evidence.
	if *dryRun || *victim == "" || *manager == "" {
		fmt.Fprintln(os.Stderr, "┌─────────────────────────────────────────────────────────────┐")
		fmt.Fprintln(os.Stderr, "│  DRY-RUN / SYNTHETIC PIPELINE — results are NOT real telemetry │")
		fmt.Fprintln(os.Stderr, "│  Missing --victim-container or --manager-container.            │")
		fmt.Fprintln(os.Stderr, "└─────────────────────────────────────────────────────────────┘")
	}

	// No registry, no run. Every technique's command comes from the vendored
	// Atomic Red Team tree; without it there is nothing honest to execute.
	reg, err := loadRegistry(*atomicsRoot, *overridesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	rules, err := mapping.LoadRuleMap(*ruleMapPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	targets, err := lab.Load(*targetsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	opts := runOpts{
		output:           *output,
		dryRun:           *dryRun,
		victimContainer:  *victim,
		managerContainer: *manager,
		registry:         reg,
		rules:            rules,
		targets:          targets,
		settleTimeout:    *settleTimeout,
		settlePoll:       *settlePoll,
	}

	switch {
	case *arbiterFile != "":
		err = runArbiter(ctx, *arbiterFile, opts)
	case *emulationFile != "":
		err = runEmulation(ctx, *emulationFile, opts)
	case *planFile != "":
		err = runCampaign(ctx, *planFile, opts)
	case *technique != "":
		err = runOne(ctx, *technique, opts)
	default:
		fmt.Fprintln(os.Stderr, "error: --technique or --plan is required")
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// loadRegistry opens the vendored Atomic Red Team tree. A run cannot proceed
// without it: with no registry there is no real command to execute, and the
// engine must never fall back to a fabricated one.
func loadRegistry(root, overrides string) (*atomic.Registry, error) {
	reg, err := atomic.Load(root, overrides)
	if err != nil {
		return nil, err
	}
	if b, err := os.ReadFile(atomicsCommitRecord); err == nil {
		reg.SetCommit(string(b))
	}
	return reg, nil
}

func newExec(dryRun bool, victimContainer string) model.Executor {
	if dryRun || victimContainer == "" {
		return executor.DryExecutor{}
	}
	return executor.DockerExecutor{Container: victimContainer}
}

func newColl(dryRun bool, managerContainer string) model.Collector {
	if dryRun || managerContainer == "" {
		return &collector.WazuhCollector{}
	}
	return &collector.WazuhCollector{ManagerContainer: managerContainer}
}

func newReporter(output string) model.Reporter {
	if strings.HasSuffix(output, ".html") {
		return report.HTMLReporter{Path: output}
	}
	if strings.HasSuffix(output, ".json") {
		return report.NavigatorLayerReporter{Path: output}
	}
	if strings.Contains(output, "reports") || strings.HasSuffix(output, "coverage") {
		return report.DashboardReporter{Dir: output}
	}
	return report.JSONReporter{Out: os.Stdout}
}

// runOpts carries the shared pipeline configuration for a run command.
type runOpts struct {
	output           string
	dryRun           bool
	victimContainer  string
	managerContainer string
	campaign         string
	settleTimeout    time.Duration
	settlePoll       time.Duration
	registry         *atomic.Registry
	rules            *mapping.RuleMap
	targets          *lab.Targets
}

// with returns a copy of the options labelled with the campaign that is running.
func (o runOpts) with(campaign string) runOpts {
	o.campaign = campaign
	return o
}

// synthetic reports whether any pipeline stage is dry/synthetic. Such a run's
// results are NOT real telemetry and must be marked non-evidentiary.
func (o runOpts) synthetic() bool {
	return o.dryRun || o.victimContainer == "" || o.managerContainer == ""
}

// runTasks drives a set of tasks through the pipeline, applying BOTH hard
// contracts in one place so no run command can bypass them:
//   - synthetic marking (dry pipeline → not real evidence), and
//   - canary gating (a real run whose positive control does not fire is
//     INCONCLUSIVE and its coverage must not be presented as valid).
func runTasks(ctx context.Context, tasks []model.TechniqueTask, o runOpts) error {
	result := model.CampaignResult{
		StartedAt:     time.Now().UTC(),
		Synthetic:     o.synthetic(),
		Campaign:      o.campaign,
		AtomicsCommit: o.registry.Commit(),
		UntestedRules: untestedFor(o.rules, tasks),
	}

	// Group work by the platform its rule-map entry declares, so a campaign can
	// span the Linux container and the Windows VM in one run. Previously every
	// technique went to a hardcoded Linux target and the Windows rule was
	// unreachable from `run`.
	byPlatform := map[string][]model.TechniqueTask{}
	var order []string
	for _, task := range tasks {
		p := o.platformFor(task.TechniqueID)
		if _, seen := byPlatform[p]; !seen {
			order = append(order, p)
		}
		byPlatform[p] = append(byPlatform[p], task)
	}

	for _, platform := range order {
		plat := o.stackFor(platform)
		if plat.err != nil {
			for _, task := range byPlatform[platform] {
				result.Chains = append(result.Chains, model.ProofChain{
					TechniqueID:     task.TechniqueID,
					SourceCVE:       task.SourceCVE,
					ArbiterPriority: task.Priority,
					Verdict:         model.Errored,
					Note:            plat.err.Error(),
				})
			}
			continue
		}

		// Canary gate, per platform. A campaign spanning two hosts must prove
		// BOTH pipelines: a healthy Linux canary says nothing about whether
		// Windows telemetry is flowing.
		if !result.Synthetic {
			cr := canary.Checker{RulesDir: "detections"}.Run(ctx, canary.NewMarker(),
				plat.exec, plat.coll, platform, plat.target)
			if !cr.Healthy {
				result.Inconclusive = true
				result.CanaryDetail = appendDetail(result.CanaryDetail, canaryFailDetail(cr))
				fmt.Fprintf(os.Stderr, "INCONCLUSIVE: %s — coverage will not be reported as valid\n",
					canaryFailDetail(cr))
			} else {
				result.CanaryHealthy = true
			}
		}

		for _, task := range byPlatform[platform] {
			chain, err := runTechnique(ctx, plat.exec, plat.coll, plat.eval, o.registry, o.rules, task,
				plat.target, collector.Settler{Timeout: o.settleTimeout, PollInterval: o.settlePoll})
			if err != nil {
				chain = model.ProofChain{TechniqueID: task.TechniqueID, Verdict: model.Errored, Note: err.Error()}
			}
			chain.SourceCVE = task.SourceCVE
			chain.ArbiterPriority = task.Priority
			result.Chains = append(result.Chains, chain)
		}
	}

	// A failed positive control on ANY platform invalidates the run: without a
	// working pipeline no per-technique verdict is trustworthy.
	if result.Inconclusive {
		result.CanaryHealthy = false
		for i := range result.Chains {
			if result.Chains[i].Verdict != model.Errored {
				result.Chains[i].Verdict = model.Inconclusive
			}
		}
	}

	labelAttribution(result.Chains, o.synthetic(), primaryHost(o))

	// Capture the raw telemetry so this run can be re-evaluated against future
	// rule changes with no lab. Synthetic runs are refused by the writer.
	if dir := captureDir(o.output, result.StartedAt); dir != "" {
		if err := capture.Write(dir, result, primaryHost(o)); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not capture telemetry: %v\n", err)
		}
	}

	return newReporter(o.output).Write(result)
}

// platformStack is the executor/collector/evaluator triple for one platform.
type platformStack struct {
	exec   model.Executor
	coll   model.Collector
	eval   model.Evaluator
	target model.Target
	err    error
}

// platformFor reports which lab platform a technique belongs on.
func (o runOpts) platformFor(technique string) string {
	if o.rules != nil {
		if e, ok := o.rules.Entry(technique); ok && e.Platform != "" {
			return strings.ToLower(e.Platform)
		}
	}
	return "linux"
}

// stackFor builds the pipeline for one platform from the lab inventory.
func (o runOpts) stackFor(platform string) platformStack {
	t, ok := o.targets.ForPlatform(platform)
	if !ok {
		return platformStack{err: fmt.Errorf(
			"no lab target declared for platform %q — add one to lab/targets.yml", platform)}
	}

	st := platformStack{
		target: t.Model(),
		eval:   evaluator.RuleMatcherEvaluator{RulesDir: orDefaultStr(t.RulesDir, "detections/"+platform)},
		coll:   newColl(o.dryRun, o.managerContainer),
	}

	switch {
	case o.synthetic():
		st.exec = executor.DryExecutor{}
	case t.Executor == "ssh":
		host, user, pass := t.SSHConfig()
		if host == "" {
			return platformStack{err: fmt.Errorf(
				"target %s needs an SSH host (set %s)", t.Name, t.SSHHostEnv)}
		}
		st.exec = &executor.SSHExecutor{Host: host, User: user, Password: pass}
	default:
		container := t.Container
		if o.victimContainer != "" {
			container = o.victimContainer
		}
		st.exec = executor.DockerExecutor{Container: container}
	}
	return st
}

// primaryHost is the host recorded on captured telemetry. A single-platform
// campaign names its target; a mixed one records none, because the dataset
// spans hosts and claiming one would be wrong.
func primaryHost(o runOpts) string {
	if t, ok := o.targets.ForPlatform("linux"); ok {
		return t.Name
	}
	return ""
}

func appendDetail(existing, add string) string {
	if existing == "" {
		return add
	}
	return existing + "; " + add
}

func orDefaultStr(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// untestedFor names every rule this campaign will not exercise, with why.
// Rules declared untested in the map keep their declared reason; a mapped rule
// whose technique is absent from this campaign is reported as not-in-campaign.
// Coverage is only honest next to what it did not cover.
func untestedFor(rules *mapping.RuleMap, tasks []model.TechniqueTask) map[string]string {
	if rules == nil {
		return nil
	}
	out := map[string]string{}
	for rule, reason := range rules.UntestedRules {
		out[rule] = reason
	}

	inCampaign := map[string]bool{}
	for _, t := range tasks {
		for _, r := range rules.ExpectedRules(t.TechniqueID) {
			inCampaign[r] = true
		}
	}
	for rule := range rules.MappedRules() {
		if !inCampaign[rule] {
			out[rule] = "not_in_campaign — mapped to a technique this plan does not run"
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// captureDir mirrors DashboardReporter's per-run layout so a run's dataset sits
// beside its coverage.json.
func captureDir(output string, startedAt time.Time) string {
	dir := output
	if dir == "" || strings.HasSuffix(dir, ".html") || strings.HasSuffix(dir, ".json") {
		dir = "reports"
	}
	runID := fmt.Sprintf("campaign-%s", startedAt.UTC().Format("20060102T150405Z"))
	return filepath.Join(dir, "runs", runID)
}

// labelAttribution records how tightly each verdict is bound to its own
// execution. Overlap is a campaign-level property — two techniques whose
// collection windows intersect can each pick up the other's events — so it can
// only be decided once every window is known.
//
// This does not change any verdict. It states the quality of the evidence
// behind one, which is the difference between a coverage number and a claim.
func labelAttribution(chains []model.ProofChain, synthetic bool, host string) {
	for i := range chains {
		c := &chains[i]

		// A synthetic pipeline produced no real telemetry, so nothing can be
		// attributed to a real execution.
		if synthetic {
			c.Attribution = model.Unscoped
			continue
		}
		// A technique that never ran has no window to scope.
		if c.Window.Start.IsZero() || c.Window.End.IsZero() {
			c.Attribution = model.Unscoped
			continue
		}

		overlapped := false
		for j := range chains {
			if i == j || chains[j].Window.Start.IsZero() {
				continue
			}
			if c.Window.Overlaps(chains[j].Window) {
				overlapped = true
				break
			}
		}
		switch {
		case overlapped:
			c.Attribution = model.WindowOverlap
		case host != "":
			c.Attribution = model.WindowAndHostScoped
		default:
			c.Attribution = model.WindowScoped
		}
	}
}

func canaryFailDetail(cr canary.Result) string {
	if cr.Err != nil {
		return fmt.Sprintf("canary not detected on %s: %v", cr.Platform, cr.Err)
	}
	return fmt.Sprintf("canary not detected on %s", cr.Platform)
}

func runCampaign(ctx context.Context, planPath string, o runOpts) error {
	var f feed.StaticFeed
	if err := f.Load(planPath); err != nil {
		return fmt.Errorf("load plan: %w", err)
	}
	tasks, err := f.Next(ctx)
	if err != nil {
		return fmt.Errorf("feed: %w", err)
	}
	return runTasks(ctx, tasks, o.with(f.Name))
}

func runArbiter(ctx context.Context, arbiterPath string, o runOpts) error {
	var f feed.ArbiterFeed
	if err := f.Load(arbiterPath); err != nil {
		return fmt.Errorf("load arbiter export: %w", err)
	}
	tasks, err := f.Next(ctx)
	if err != nil {
		return fmt.Errorf("arbiter feed: %w", err)
	}
	return runTasks(ctx, tasks, o.with("arbiter"))
}

func runEmulation(ctx context.Context, emuPath string, o runOpts) error {
	plan, err := feed.LoadEmulation(emuPath)
	if err != nil {
		return fmt.Errorf("load emulation: %w", err)
	}
	var tasks []model.TechniqueTask
	for _, stage := range plan.Stages {
		tasks = append(tasks, stage.ToTasks()...)
	}
	return runTasks(ctx, tasks, o.with(plan.Name))
}

func runOne(ctx context.Context, technique string, o runOpts) error {
	// Deliberately leave AtomicIDs empty so atomicIDFor consults the rule map.
	// Synthesizing "<technique>-1" here pre-empted it and picked ART's first
	// test, which for most techniques is the WINDOWS one — `--technique T1082`
	// resolved to a command_prompt atomic and errored on the Linux victim, even
	// though the rule map names T1082-3.
	task := model.TechniqueTask{TechniqueID: technique}
	return runTasks(ctx, []model.TechniqueTask{task}, o.with(technique))
}

// atomicIDFor picks the atomic this task should run: the plan's choice first,
// then the mapping's. Only if neither declares one does it guess the
// technique's first test — and the resolved test's platform is still checked
// before anything executes.
func atomicIDFor(task model.TechniqueTask, rules *mapping.RuleMap) string {
	if len(task.AtomicIDs) > 0 && strings.TrimSpace(task.AtomicIDs[0]) != "" {
		return strings.TrimSpace(task.AtomicIDs[0])
	}
	if rules != nil {
		if id := rules.AtomicFor(task.TechniqueID); id != "" {
			return id
		}
	}
	return task.TechniqueID + "-1"
}

// unmetPrereq runs each dependency's prereq_command on the target and returns a
// description of the first one that fails. A technique whose prerequisites are
// not met never ran, so it is SKIPPED_PREREQ — reporting it as MISSED would
// invent a detection gap out of an unmet dependency.
func unmetPrereq(ctx context.Context, exec model.Executor, test atomic.Test, target model.Target) string {
	for _, dep := range test.Dependencies {
		if dep.PrereqCommand == "" {
			continue
		}
		probe := model.AtomicTest{
			ID:          test.ID + "-prereq",
			TechniqueID: test.TechniqueID,
			Command:     dep.PrereqCommand,
			Executor:    test.DependencyExecutor,
		}
		res, err := exec.Run(ctx, probe, target)
		if err != nil {
			return fmt.Sprintf("prerequisite check failed to run (%s): %v", dep.Description, err)
		}
		if res.ExitCode != 0 {
			desc := dep.Description
			if desc == "" {
				desc = dep.PrereqCommand
			}
			return "unmet prerequisite: " + desc
		}
	}
	return ""
}

// runTechnique resolves the task's atomic to a REAL command, runs it, collects
// telemetry and evaluates the mapped rule.
//
// Resolution is strict on purpose. Every failure below returns a verdict that
// names what went wrong rather than a coverage number: an unresolvable atomic,
// a platform mismatch and an unmet prerequisite are all reasons a detection was
// never exercised, and none of them is evidence that a detection is missing.
func runTechnique(ctx context.Context, exec model.Executor, coll model.Collector, eval model.Evaluator,
	reg *atomic.Registry, rules *mapping.RuleMap, task model.TechniqueTask, target model.Target,
	settler collector.Settler) (model.ProofChain, error) {

	atomicID := atomicIDFor(task, rules)
	chain := model.ProofChain{TechniqueID: task.TechniqueID}

	test, err := reg.Resolve(atomicID)
	if err != nil {
		chain.Verdict = model.Errored
		chain.Note = err.Error()
		return chain, nil
	}

	chain.Atomic = model.AtomicTest{
		ID:             test.ID,
		TechniqueID:    test.TechniqueID,
		Name:           test.Name,
		GUID:           test.GUID,
		Command:        test.Command,
		CleanupCommand: test.CleanupCommand,
		Executor:       test.Executor,
		Source:         test.Source,
		OverrideReason: test.OverrideReason,
	}

	if !test.SupportsPlatform(target.Kind) {
		chain.Verdict = model.Errored
		chain.Note = fmt.Sprintf("atomic %s supports %v, but target %s is %s — fix the plan's atomic_ids",
			test.ID, test.SupportedPlatforms, target.Host, target.Kind)
		return chain, nil
	}

	if unmet := unmetPrereq(ctx, exec, test, target); unmet != "" {
		chain.Verdict = model.SkippedPrereq
		chain.Note = unmet
		return chain, nil
	}

	run, err := exec.Run(ctx, chain.Atomic, target)
	if err != nil {
		return chain, fmt.Errorf("execute: %w", err)
	}
	chain.ExecutedAt = run.StartedAt

	// Cleanup is best-effort per atomic after run.
	_ = exec.Cleanup(ctx, chain.Atomic, target)

	window := run.Window(collectWindow)
	chain.Window = window

	expected := rules.ExpectedRules(task.TechniqueID)
	chain.RulesExpected = expected
	if len(expected) == 0 {
		chain.Verdict = model.Errored
		chain.Note = "no Sigma rule mapped for " + task.TechniqueID + " in the rule map"
		return chain, nil
	}

	// Poll until an expected rule matches or ingestion settles, rather than
	// sleeping a fixed interval and querying once.
	settled, err := settler.Settle(ctx, coll, window, target.Host,
		func(events []model.Event) bool {
			v, _, _, err := evaluateExpected(eval, expected, task.TechniqueID, events)
			return err == nil && v == model.Detected
		})
	if err != nil {
		return chain, fmt.Errorf("collect: %w", err)
	}
	events := settled.Events
	chain.EventsCollected = len(events)
	chain.Collected = events
	if settled.TimedOut && len(events) == 0 {
		chain.Note = fmt.Sprintf("no telemetry arrived within %s of execution", settled.Waited.Round(time.Second))
	}

	// A technique is DETECTED when ANY expected rule matches. Evaluating only
	// the first would understate coverage whenever a second rule is the one that
	// legitimately catches the behaviour.
	verdict, evidence, matched, err := evaluateExpected(eval, expected, task.TechniqueID, events)
	if err != nil {
		return chain, fmt.Errorf("evaluate: %w", err)
	}

	chain.Verdict = verdict
	chain.Evidence = evidence
	chain.RulesMatched = matched
	if len(matched) > 0 {
		chain.RuleMatched = matched[0]
		chain.DetectLatencyMS = detectLatency(run.StartedAt, evidence)
	}
	return chain, nil
}

// evaluateExpected runs every expected rule and reports the best outcome. The
// verdict precedence is DETECTED > MISSED > INCONCLUSIVE > NO_TELEMETRY: a rule
// that matched is proof of detection regardless of what the others did, while
// NO_TELEMETRY only stands if no rule ever saw usable events.
func evaluateExpected(eval model.Evaluator, expected []string, title string, events []model.Event) (
	model.Verdict, []model.Event, []string, error) {

	best := model.NoTelemetry
	var evidence []model.Event
	var matched []string

	rank := map[model.Verdict]int{
		model.NoTelemetry:  0,
		model.Inconclusive: 1,
		model.Missed:       2,
		model.Detected:     3,
	}

	for _, path := range expected {
		v, ev, err := eval.Evaluate(model.SigmaRule{Path: path, Title: title}, events)
		if err != nil {
			return model.Errored, nil, nil, err
		}
		if v == model.Detected {
			matched = append(matched, path)
			evidence = append(evidence, ev...)
		}
		if rank[v] > rank[best] {
			best = v
		}
	}
	return best, evidence, matched, nil
}

// detectLatency is the gap between execution start and the earliest matching
// event — how long the pipeline took to make the behaviour visible.
func detectLatency(start time.Time, evidence []model.Event) int64 {
	earliest := time.Time{}
	for _, e := range evidence {
		if e.Timestamp.IsZero() {
			continue
		}
		if earliest.IsZero() || e.Timestamp.Before(earliest) {
			earliest = e.Timestamp
		}
	}
	if earliest.IsZero() || earliest.Before(start) {
		return 0
	}
	return earliest.Sub(start).Milliseconds()
}

func runCanaryCmd() {
	marker := canary.NewMarker()
	ctx := context.Background()

	// The Windows host comes from the lab inventory, not from a literal here.
	// It used to default to 192.168.88.13, an address that only existed on one
	// machine's bridged network — on any other host the canary silently probed
	// something that was not the victim, or nothing at all.
	targets, err := lab.Load(defaultTargets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	t, ok := targets.ForPlatform("windows")
	if !ok {
		fmt.Fprintf(os.Stderr, "error: no windows target declared in %s\n", defaultTargets)
		os.Exit(1)
	}
	sshHost, sshUser, sshPass := t.SSHConfig()
	if sshHost == "" {
		fmt.Fprintf(os.Stderr,
			"error: no address for the windows victim. Set %s to the IP the VM "+
				"actually has (run `ipconfig` on it) — there is no default, because a\n"+
				"wrong one probes a host that is not your victim.\n", t.SSHHostEnv)
		os.Exit(1)
	}

	exec := &executor.SSHExecutor{Host: sshHost, User: sshUser, Password: sshPass}
	coll := &collector.WazuhCollector{ManagerContainer: "single-node-wazuh.manager-1"}
	target := model.Target{Host: "windows-vm", Kind: "windows"}

	fmt.Printf("Canary marker: %s\n", marker)
	result := canary.Check(ctx, marker, exec, coll, "windows", target)
	if result.Healthy {
		fmt.Printf("Canary: DETECTED on %s (evidence: %d events)\n", result.Platform, len(result.Evidence))
	} else {
		fmt.Printf("Canary: NOT DETECTED on %s — pipeline broken\n", result.Platform)
		if result.Err != nil {
			fmt.Printf("Error: %v\n", result.Err)
		}
		os.Exit(1)
	}
}

func runServe() {
	addr := flag.NewFlagSet("serve", flag.ExitOnError)
	host := addr.String("addr", "127.0.0.1:8787", "listen address")
	reports := addr.String("reports", "reports", "reports directory")
	allowRemote := addr.Bool("allow-remote", false, "allow non-loopback binding")
	if err := addr.Parse(os.Args[2:]); err != nil {
		fmt.Fprintf(os.Stderr, "error parsing serve flags: %v\n", err)
		os.Exit(2)
	}

	if !isLoopback(*host) && !*allowRemote {
		fmt.Fprintf(os.Stderr, "refusing to bind %s — not loopback. Use --allow-remote to override.\n", *host)
		os.Exit(1)
	}

	handler := server.New(*reports)
	srv := &http.Server{
		Addr:              *host,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	fmt.Printf("Purple Loop dashboard: http://%s\n", *host)
	log.Fatal(srv.ListenAndServe())
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
