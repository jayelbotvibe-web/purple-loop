package lab

import (
	"testing"
)

const shipped = "../../lab/targets.yml"

func TestShippedInventoryCoversBothPlatforms(t *testing.T) {
	ts, err := Load(shipped)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, kind := range []string{"linux", "windows"} {
		tgt, ok := ts.ForPlatform(kind)
		if !ok {
			t.Errorf("no %s target declared — the cross-platform claim needs one", kind)
			continue
		}
		if tgt.RulesDir == "" {
			t.Errorf("%s target declares no rules_dir", kind)
		}
	}
}

// Credentials must come from the environment. The Windows host used to be a
// literal in cmd/purpleloop/main.go.
func TestSSHConfigPrefersEnvironment(t *testing.T) {
	ts, err := Load(shipped)
	if err != nil {
		t.Fatal(err)
	}
	win, ok := ts.ForPlatform("windows")
	if !ok {
		t.Fatal("no windows target")
	}
	if win.SSHHostEnv == "" || win.SSHPassEnv == "" {
		t.Fatal("the windows target must read host and password from the environment")
	}

	t.Setenv(win.SSHHostEnv, "10.0.0.5")
	t.Setenv(win.SSHUserEnv, "lab-user")
	t.Setenv(win.SSHPassEnv, "from-env")

	host, user, pass := win.SSHConfig()
	if host != "10.0.0.5" || user != "lab-user" || pass != "from-env" {
		t.Errorf("SSHConfig = (%s,%s,%s), want the environment values", host, user, pass)
	}
}

// A password must never come from a default — only from the environment.
func TestSSHPasswordIsNeverDefaulted(t *testing.T) {
	ts, err := Load(shipped)
	if err != nil {
		t.Fatal(err)
	}
	win, _ := ts.ForPlatform("windows")
	t.Setenv(win.SSHPassEnv, "")
	if _, _, pass := win.SSHConfig(); pass != "" {
		t.Errorf("password = %q with an empty env var; it must not fall back to a literal", pass)
	}
}

func TestForPlatformUnknownKind(t *testing.T) {
	ts, err := Load(shipped)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ts.ForPlatform("macos"); ok {
		t.Error("an undeclared platform must not resolve to a target")
	}
}

func TestLoadRejectsMissingFile(t *testing.T) {
	if _, err := Load("nope.yml"); err == nil {
		t.Error("a missing inventory must error")
	}
}
