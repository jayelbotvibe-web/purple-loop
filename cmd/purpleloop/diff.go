package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// runDiff compares two runs and reports what changed per technique.
//
// A coverage percentage that moves from 80% to 70% tells you something broke
// but not what. This names it: "T1082 regressed DETECTED -> MISSED". That is
// the output detection engineering actually acts on, and it was impossible
// while the history index stored only a percentage.
func runDiff() {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	failOnRegression := fs.Bool("fail-on-regression", false, "exit non-zero if any technique regressed")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}
	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: purpleloop diff [--fail-on-regression] <run-a> <run-b>")
		fmt.Fprintln(os.Stderr, "  each argument is a run directory or its coverage.json")
		fmt.Fprintln(os.Stderr, "  flags must precede the run paths")
		os.Exit(2)
	}

	before, err := readCoverage(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	after, err := readCoverage(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	regressions, improvements, other := compareRuns(before, after)

	fmt.Printf("%s  ->  %s\n\n", fs.Arg(0), fs.Arg(1))
	printChanges("REGRESSED", regressions)
	printChanges("IMPROVED", improvements)
	printChanges("CHANGED", other)

	if len(regressions)+len(improvements)+len(other) == 0 {
		fmt.Println("No per-technique changes.")
	}
	if *failOnRegression && len(regressions) > 0 {
		os.Exit(1)
	}
}

type change struct{ Technique, From, To string }

// verdictRank orders outcomes by how much detection they demonstrate, so a
// move down the scale is a regression. Verdicts that mean "never exercised"
// deliberately share the bottom: moving between them is a change worth showing
// but is not a detection regression.
var verdictRank = map[string]int{
	"ERROR":          0,
	"SKIPPED_PREREQ": 0,
	"INCONCLUSIVE":   0,
	"NO_TELEMETRY":   1,
	"MISSED":         2,
	"DETECTED":       3,
}

func compareRuns(before, after map[string]string) (regressions, improvements, other []change) {
	seen := map[string]bool{}
	for t := range before {
		seen[t] = true
	}
	for t := range after {
		seen[t] = true
	}
	techniques := make([]string, 0, len(seen))
	for t := range seen {
		techniques = append(techniques, t)
	}
	sort.Strings(techniques)

	for _, t := range techniques {
		from, okB := before[t]
		to, okA := after[t]
		switch {
		case !okB:
			other = append(other, change{t, "(absent)", to})
			continue
		case !okA:
			other = append(other, change{t, from, "(absent)"})
			continue
		case from == to:
			continue
		}
		c := change{t, from, to}
		switch {
		case verdictRank[to] < verdictRank[from]:
			regressions = append(regressions, c)
		case verdictRank[to] > verdictRank[from]:
			improvements = append(improvements, c)
		default:
			other = append(other, c)
		}
	}
	return regressions, improvements, other
}

func printChanges(label string, cs []change) {
	if len(cs) == 0 {
		return
	}
	fmt.Printf("%s (%d)\n", label, len(cs))
	for _, c := range cs {
		fmt.Printf("  %-12s %s -> %s\n", c.Technique, c.From, c.To)
	}
	fmt.Println()
}

// readCoverage loads a run's per-technique verdicts from its coverage.json.
func readCoverage(path string) (map[string]string, error) {
	if fi, err := os.Stat(path); err == nil && fi.IsDir() {
		path = filepath.Join(path, "coverage.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read run: %w", err)
	}
	var doc struct {
		Techniques []struct {
			ID      string `json:"id"`
			Verdict string `json:"verdict"`
		} `json:"techniques"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(doc.Techniques) == 0 {
		return nil, fmt.Errorf("%s has no technique results", path)
	}
	out := make(map[string]string, len(doc.Techniques))
	for _, t := range doc.Techniques {
		out[t.ID] = t.Verdict
	}
	return out, nil
}
