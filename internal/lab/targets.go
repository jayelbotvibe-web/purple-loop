// Package lab describes the hosts a campaign can dispatch techniques to.
//
// The engine previously hardcoded one Linux target in the run path, so a
// Windows rule could never be exercised by `run` even though the executor and
// the rule both existed. Targets are configuration now, and credentials are
// read from the environment rather than compiled into the binary.
package lab

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

// Target is one lab host and how to reach it.
type Target struct {
	Name      string `yaml:"name"`
	Kind      string `yaml:"kind"`
	Executor  string `yaml:"executor"` // "docker" | "ssh"
	Container string `yaml:"container"`
	RulesDir  string `yaml:"rules_dir"`

	SSHHostEnv  string `yaml:"ssh_host_env"`
	SSHUserEnv  string `yaml:"ssh_user_env"`
	SSHPassEnv  string `yaml:"ssh_pass_env"`
	DefaultHost string `yaml:"default_host"`
	DefaultUser string `yaml:"default_user"`
}

// Targets is the lab inventory.
type Targets struct {
	Targets []Target `yaml:"targets"`
}

// Load reads the lab target inventory.
func Load(path string) (*Targets, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read targets: %w", err)
	}
	var t Targets
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("parse targets %s: %w", path, err)
	}
	if len(t.Targets) == 0 {
		return nil, fmt.Errorf("targets %s declares no hosts", path)
	}
	for i, tt := range t.Targets {
		if tt.Name == "" || tt.Kind == "" || tt.Executor == "" {
			return nil, fmt.Errorf("target %d needs name, kind and executor", i)
		}
	}
	return &t, nil
}

// ForPlatform returns the target that runs a given platform's techniques.
func (t *Targets) ForPlatform(kind string) (Target, bool) {
	for _, tt := range t.Targets {
		if strings.EqualFold(tt.Kind, kind) {
			return tt, true
		}
	}
	return Target{}, false
}

// Kinds lists the distinct platforms the inventory can reach.
func (t *Targets) Kinds() []string {
	seen := map[string]bool{}
	var out []string
	for _, tt := range t.Targets {
		k := strings.ToLower(tt.Kind)
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// Model converts to the engine's target type.
func (t Target) Model() model.Target {
	return model.Target{Host: t.Name, Kind: t.Kind}
}

// SSHConfig resolves connection details from the environment, falling back to
// the declared defaults. A password is never defaulted.
func (t Target) SSHConfig() (host, user, pass string) {
	host = envOr(t.SSHHostEnv, t.DefaultHost)
	user = envOr(t.SSHUserEnv, t.DefaultUser)
	if t.SSHPassEnv != "" {
		pass = os.Getenv(t.SSHPassEnv)
	}
	return host, user, pass
}

func envOr(key, def string) string {
	if key != "" {
		if v := os.Getenv(key); v != "" {
			return v
		}
	}
	return def
}
