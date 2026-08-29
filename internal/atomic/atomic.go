// Package atomic resolves Atomic Red Team test IDs (e.g. "T1082-3") into the
// concrete command that will run on a victim.
//
// This package exists because the engine previously fabricated its input: every
// technique executed the same hardcoded "id; whoami" regardless of which atomic
// the plan named, so every verdict but one was about a command nobody asked for.
// Resolution here is strict by design — an ID that cannot be resolved is an
// error the caller must surface, never a silent fallback to some default
// command. A fabricated input produces a fabricated verdict.
package atomic

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Source records where a resolved test's command came from, so a report can
// show that a lab-specific substitution was made rather than hiding it.
const (
	SourceART      = "atomic-red-team"
	SourceOverride = "override"
)

// Dependency is a prerequisite an atomic needs before it can run.
type Dependency struct {
	Description      string `yaml:"description"`
	PrereqCommand    string `yaml:"prereq_command"`
	GetPrereqCommand string `yaml:"get_prereq_command"`
}

// InputArg is a declared input with its default value.
type InputArg struct {
	Description string `yaml:"description"`
	Type        string `yaml:"type"`
	Default     any    `yaml:"default"`
}

// Test is one resolved atomic: the real command, executor and cleanup.
type Test struct {
	ID                 string
	Index              int
	GUID               string
	Name               string
	TechniqueID        string
	Description        string
	SupportedPlatforms []string
	Executor           string
	Command            string
	CleanupCommand     string
	ElevationRequired  bool
	Dependencies       []Dependency
	DependencyExecutor string
	Source             string
	OverrideReason     string
}

// SupportsPlatform reports whether the test declares support for a target kind
// ("linux", "windows", "macos").
func (t Test) SupportsPlatform(kind string) bool {
	for _, p := range t.SupportedPlatforms {
		if strings.EqualFold(p, kind) {
			return true
		}
	}
	return false
}

// ---- on-disk ART schema ----

type artFile struct {
	AttackTechnique string    `yaml:"attack_technique"`
	DisplayName     string    `yaml:"display_name"`
	AtomicTests     []artTest `yaml:"atomic_tests"`
}

type artTest struct {
	Name               string              `yaml:"name"`
	GUID               string              `yaml:"auto_generated_guid"`
	Description        string              `yaml:"description"`
	SupportedPlatforms []string            `yaml:"supported_platforms"`
	InputArguments     map[string]InputArg `yaml:"input_arguments"`
	DependencyExecutor string              `yaml:"dependency_executor_name"`
	Dependencies       []Dependency        `yaml:"dependencies"`
	Executor           artExecutor         `yaml:"executor"`
}

type artExecutor struct {
	Name              string `yaml:"name"`
	Command           string `yaml:"command"`
	CleanupCommand    string `yaml:"cleanup_command"`
	ElevationRequired bool   `yaml:"elevation_required"`
}

// ---- overrides ----

// Override adjusts an ART atomic that cannot run truthfully in this lab. Every
// override carries a reason, which the report shows, so the change stays
// visible.
//
// There are two kinds, and the narrower one is preferred:
//
//   - InputArguments alone pins an upstream atomic's declared inputs (the
//     mechanism ART itself provides) while keeping its command. Use this to
//     keep a test inside the lab network.
//   - Command replaces the atomic wholesale. Only for a technique with no
//     usable upstream test on this platform.
type Override struct {
	Reason             string            `yaml:"reason"`
	Command            string            `yaml:"command"`
	Executor           string            `yaml:"executor"`
	CleanupCommand     string            `yaml:"cleanup_command"`
	SupportedPlatforms []string          `yaml:"supported_platforms"`
	Name               string            `yaml:"name"`
	InputArguments     map[string]string `yaml:"input_arguments"`
}

type overrideFile struct {
	Overrides map[string]Override `yaml:"overrides"`
}

// Registry resolves atomic IDs against a vendored ART tree plus lab overrides.
type Registry struct {
	root      string
	commit    string
	overrides map[string]Override
}

// Load opens a vendored Atomic Red Team checkout. root is the repository root
// (the directory containing "atomics"). overridePath may be empty.
func Load(root, overridePath string) (*Registry, error) {
	atomicsDir := filepath.Join(root, "atomics")
	if fi, err := os.Stat(atomicsDir); err != nil || !fi.IsDir() {
		return nil, fmt.Errorf("atomic red team not vendored at %s — run 'make atomics'", root)
	}
	r := &Registry{root: root, overrides: map[string]Override{}}

	// Best effort: the recorded commit makes a report reproducible.
	if b, err := os.ReadFile(filepath.Join(root, "COMMIT")); err == nil {
		r.commit = strings.TrimSpace(string(b))
	}

	if overridePath != "" {
		if err := r.loadOverrides(overridePath); err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *Registry) loadOverrides(path string) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil // overrides are optional
	}
	if err != nil {
		return fmt.Errorf("read overrides: %w", err)
	}
	var f overrideFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("parse overrides %s: %w", path, err)
	}
	for id, o := range f.Overrides {
		if strings.TrimSpace(o.Reason) == "" {
			return fmt.Errorf("override %s has no reason — every substitution must be justified", id)
		}
		if strings.TrimSpace(o.Command) == "" && len(o.InputArguments) == 0 {
			return fmt.Errorf("override %s must set either command or input_arguments", id)
		}
		r.overrides[id] = o
	}
	return nil
}

// SetCommit records the vendored ART revision for reporting.
func (r *Registry) SetCommit(c string) { r.commit = strings.TrimSpace(c) }

// Commit returns the vendored ART revision, or "" if unknown.
func (r *Registry) Commit() string { return r.commit }

var idRe = regexp.MustCompile(`^(T\d{4}(?:\.\d{3})?)-(\d+)$`)

// ParseID splits an atomic ID such as "T1069.001-1" into its technique and
// 1-based test index.
func ParseID(atomicID string) (technique string, index int, err error) {
	m := idRe.FindStringSubmatch(strings.TrimSpace(atomicID))
	if m == nil {
		return "", 0, fmt.Errorf("malformed atomic id %q (want e.g. T1082-3)", atomicID)
	}
	i, _ := strconv.Atoi(m[2])
	if i < 1 {
		return "", 0, fmt.Errorf("atomic index in %q must be 1-based", atomicID)
	}
	return m[1], i, nil
}

// Resolve returns the concrete test for an atomic ID. Overrides win over the
// vendored tree; an unresolvable ID is an error, never a default command.
func (r *Registry) Resolve(atomicID string) (Test, error) {
	technique, index, err := ParseID(atomicID)
	if err != nil {
		return Test{}, err
	}

	o, overridden := r.overrides[atomicID]
	if overridden && strings.TrimSpace(o.Command) != "" {
		platforms := o.SupportedPlatforms
		if len(platforms) == 0 {
			platforms = []string{"linux"}
		}
		name := o.Name
		if name == "" {
			name = "lab override for " + atomicID
		}
		return Test{
			ID:                 atomicID,
			Index:              index,
			Name:               name,
			TechniqueID:        technique,
			SupportedPlatforms: platforms,
			Executor:           orDefault(o.Executor, "sh"),
			Command:            strings.TrimSpace(o.Command),
			CleanupCommand:     strings.TrimSpace(o.CleanupCommand),
			Source:             SourceOverride,
			OverrideReason:     o.Reason,
		}, nil
	}

	path := filepath.Join(r.root, "atomics", technique, technique+".yaml")
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Test{}, fmt.Errorf("technique %s has no atomics in the vendored tree (%s)", technique, path)
	}
	if err != nil {
		return Test{}, fmt.Errorf("read %s: %w", path, err)
	}

	var f artFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return Test{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if index > len(f.AtomicTests) {
		return Test{}, fmt.Errorf("%s: technique %s has %d atomic tests, index %d requested",
			atomicID, technique, len(f.AtomicTests), index)
	}

	at := f.AtomicTests[index-1]
	subst := defaults(at.InputArguments)

	// An input-only override pins declared inputs (e.g. a ping target) without
	// touching the upstream command, so the test stays the upstream test.
	pinned := ""
	if overridden {
		keys := make([]string, 0, len(o.InputArguments))
		for k, v := range o.InputArguments {
			subst[k] = v
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 0 {
			pinned = fmt.Sprintf("inputs pinned (%s): %s", strings.Join(keys, ", "), o.Reason)
		}
	}

	deps := make([]Dependency, 0, len(at.Dependencies))
	for _, d := range at.Dependencies {
		deps = append(deps, Dependency{
			Description:      strings.TrimSpace(interpolate(d.Description, subst)),
			PrereqCommand:    strings.TrimSpace(interpolate(d.PrereqCommand, subst)),
			GetPrereqCommand: strings.TrimSpace(interpolate(d.GetPrereqCommand, subst)),
		})
	}

	return Test{
		ID:                 atomicID,
		Index:              index,
		GUID:               at.GUID,
		Name:               at.Name,
		TechniqueID:        technique,
		Description:        strings.TrimSpace(at.Description),
		SupportedPlatforms: at.SupportedPlatforms,
		Executor:           orDefault(at.Executor.Name, "sh"),
		Command:            strings.TrimSpace(interpolate(at.Executor.Command, subst)),
		CleanupCommand:     strings.TrimSpace(interpolate(at.Executor.CleanupCommand, subst)),
		ElevationRequired:  at.Executor.ElevationRequired,
		Dependencies:       deps,
		DependencyExecutor: orDefault(at.DependencyExecutor, orDefault(at.Executor.Name, "sh")),
		Source:             SourceART,
		OverrideReason:     pinned,
	}, nil
}

// defaults flattens declared input arguments to their default values.
func defaults(args map[string]InputArg) map[string]string {
	out := make(map[string]string, len(args))
	for k, v := range args {
		if v.Default == nil {
			out[k] = ""
			continue
		}
		out[k] = strings.TrimSpace(fmt.Sprintf("%v", v.Default))
	}
	return out
}

var placeholderRe = regexp.MustCompile(`#\{([a-zA-Z0-9_]+)\}`)

// interpolate substitutes #{name} placeholders with their defaults. ART allows
// a default to itself contain a placeholder, so it resolves iteratively; the
// bound stops a self-referential default from looping forever.
func interpolate(s string, subst map[string]string) string {
	if s == "" || len(subst) == 0 {
		return s
	}
	for i := 0; i < 5; i++ {
		replaced := placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
			key := placeholderRe.FindStringSubmatch(m)[1]
			if v, ok := subst[key]; ok {
				return v
			}
			return m // unknown placeholder stays visible rather than silently emptied
		})
		if replaced == s {
			break
		}
		s = replaced
	}
	return s
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}
