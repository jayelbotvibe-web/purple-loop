package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/jayelbotvibe-web/purple-loop/internal/evaluator"
	"github.com/jayelbotvibe-web/purple-loop/internal/precision"
)

// runPrecision measures the false-positive rate of the shipped detections
// against a benign administrator workload.
//
// Coverage answers "does it fire when it should". This answers "does it stay
// quiet when it should", which coverage alone cannot: a rule matching
// everything scores 100% coverage and is useless. Reported together, they are
// a claim about a detection set; reported alone, coverage is a half-truth.
func runPrecision() {
	fs := flag.NewFlagSet("precision", flag.ExitOnError)
	baseline := fs.String("baseline", "emulation/benign-baseline.yml", "benign workload definition")
	rulesDir := fs.String("rules-dir", "detections/linux", "rules to measure")
	asJSON := fs.Bool("json", false, "emit JSON instead of a table")
	if err := fs.Parse(os.Args[2:]); err != nil {
		os.Exit(2)
	}

	b, err := precision.LoadBaseline(*baseline)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	res, err := precision.Measure(evaluator.RuleMatcherEvaluator{RulesDir: *rulesDir}, *rulesDir, b)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Printf("Precision: %d%%  (%d benign commands, %d rules)\n",
			res.PrecisionPct, res.CommandsRun, res.RulesChecked)
		if len(res.FalsePositives) == 0 {
			fmt.Println("No rule fired on benign activity.")
		}
		for _, fp := range res.FalsePositives {
			fmt.Printf("  FALSE POSITIVE  %s\n                  fired on %q (%s)\n",
				fp.Rule, fp.Command, fp.Category)
		}
	}

	// A false positive is a finding, not a note: exit non-zero so this gates CI
	// and a release the same way a failing detection would.
	if len(res.FalsePositives) > 0 {
		os.Exit(1)
	}
}
