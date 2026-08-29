// Package precision measures false positives: whether detections stay silent
// during ordinary administration.
//
// Coverage without a false-positive rate is half a metric. A rule that matches
// everything scores perfect coverage and is worthless. The repository's
// negative fixtures prove a rule rejects an event crafted to be rejected, which
// is a claim about the author's intent; this measures the rule against a
// workload written independently of it.
package precision

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// Command is one benign action and the process-creation event it produces.
type Command struct {
	Category    string `yaml:"category"`
	Command     string `yaml:"command"`
	Image       string `yaml:"image"`
	CommandLine string `yaml:"command_line"`
}

// Baseline is the benign workload.
type Baseline struct {
	Name        string    `yaml:"name"`
	Description string    `yaml:"description"`
	Commands    []Command `yaml:"commands"`
}

// LoadBaseline reads the benign workload definition.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	var b Baseline
	if err := yaml.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("parse baseline %s: %w", path, err)
	}
	if len(b.Commands) == 0 {
		return nil, fmt.Errorf("baseline %s declares no commands", path)
	}
	for i, c := range b.Commands {
		if c.Image == "" || c.CommandLine == "" {
			return nil, fmt.Errorf("baseline entry %d (%q) needs both image and command_line", i, c.Command)
		}
	}
	return &b, nil
}

// Event renders a benign command as the process-creation event it would emit.
func (c Command) Event() model.Event {
	raw, _ := json.Marshal(map[string]string{
		"Image":       c.Image,
		"ParentImage": "/bin/bash",
		"CommandLine": c.CommandLine,
		"User":        "root",
	})
	return model.Event{ID: "benign-" + c.Image, Raw: raw}
}

// FalsePositive is one rule firing on one benign command.
type FalsePositive struct {
	Rule     string `json:"rule"`
	Command  string `json:"command"`
	Category string `json:"category"`
}

// Result is the outcome of a precision run.
type Result struct {
	Baseline       string          `json:"baseline"`
	CommandsRun    int             `json:"commands_run"`
	RulesChecked   int             `json:"rules_checked"`
	FalsePositives []FalsePositive `json:"false_positives"`
	// PrecisionPct is the share of benign commands that fired no rule at all.
	PrecisionPct int `json:"precision_pct"`
}

// Measure evaluates every rule against every benign command. A rule that fires
// is a false positive named with the command that triggered it, so the finding
// is actionable rather than a bare number.
func Measure(eval model.Evaluator, rulesDir string, b *Baseline) (*Result, error) {
	rules, err := listRules(rulesDir)
	if err != nil {
		return nil, err
	}

	res := &Result{Baseline: b.Name, CommandsRun: len(b.Commands), RulesChecked: len(rules)}
	noisy := map[string]bool{}

	for _, c := range b.Commands {
		events := []model.Event{c.Event()}
		for _, rule := range rules {
			verdict, _, err := eval.Evaluate(model.SigmaRule{Path: rule, Title: rule}, events)
			if err != nil {
				return nil, fmt.Errorf("evaluate %s: %w", rule, err)
			}
			if verdict == model.Detected {
				res.FalsePositives = append(res.FalsePositives, FalsePositive{
					Rule: rule, Command: c.Command, Category: c.Category,
				})
				noisy[c.Command] = true
			}
		}
	}

	clean := len(b.Commands) - len(noisy)
	if len(b.Commands) > 0 {
		res.PrecisionPct = clean * 100 / len(b.Commands)
	}
	sort.Slice(res.FalsePositives, func(i, j int) bool {
		if res.FalsePositives[i].Rule != res.FalsePositives[j].Rule {
			return res.FalsePositives[i].Rule < res.FalsePositives[j].Rule
		}
		return res.FalsePositives[i].Command < res.FalsePositives[j].Command
	})
	return res, nil
}

func listRules(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules dir: %w", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}
