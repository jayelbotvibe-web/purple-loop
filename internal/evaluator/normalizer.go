package evaluator

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Normalizer maps Wazuh event JSON to canonical Sigma field names.
// Field mappings are derived from real captured events.
type Normalizer struct{}

// Reserved keys and fidelity levels attached to a normalized event.
//
// FidelityKey records where the canonical fields came from, so the evaluator
// can refuse to treat command-output or metadata scraping as genuine
// process-creation evidence. This is what keeps a DETECTED verdict honest:
// a log line that merely mentions a binary name is not proof that the process
// actually ran.
const (
	FidelityKey = "__source_fidelity__"

	// FidelityProcess marks fields sourced from real process-creation
	// telemetry (Sysmon/EventChannel eventdata, auditd execve, or a synthetic
	// process event with top-level fields).
	FidelityProcess = "process_creation"

	// FidelityLog marks fields scraped from command-output or metadata
	// (full_log, decoder name). Usable for text/keyword rules, but NOT
	// accepted as process-creation evidence.
	FidelityLog = "log"
)

// Normalize converts a raw Wazuh event into a flat map of canonical fields.
// The reserved FidelityKey entry records the highest-fidelity source that
// contributed a field (see the Fidelity* constants).
func (Normalizer) Normalize(raw json.RawMessage) map[string]string {
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil
	}
	out := make(map[string]string)
	highFidelity := false
	lowFidelity := false

	// Top-level canonical fields (dry-run, fixtures, synthetic process events)
	getString(event, "Image", &out, "Image")
	getString(event, "ParentImage", &out, "ParentImage")
	getString(event, "CommandLine", &out, "CommandLine")
	getString(event, "User", &out, "User")
	if out["Image"] != "" || out["CommandLine"] != "" {
		highFidelity = true
	}

	// Try Windows Sysmon / EventChannel paths
	if data, ok := event["data"].(map[string]any); ok {
		if win, ok := data["win"].(map[string]any); ok {
			if ed, ok := win["eventdata"].(map[string]any); ok {
				// Sysmon process creation (sysmon 1)
				getString(ed, "image", &out, "Image")
				getString(ed, "parentImage", &out, "ParentImage")
				getString(ed, "commandLine", &out, "CommandLine")
				getString(ed, "user", &out, "User")
				getString(ed, "parentUser", &out, "User")
				// Security Audit fallbacks
				getString(ed, "callerProcessName", &out, "Image")
				getString(ed, "subjectUserName", &out, "User")
				getString(ed, "processName", &out, "Image")
				highFidelity = true
			}
		}
	}

	// Try Linux auditd paths
	if data, ok := event["data"].(map[string]any); ok {
		if audit, ok := data["audit"].(map[string]any); ok {
			getString(audit, "exe", &out, "Image")
			getString(audit, "uid", &out, "User")
			getString(audit, "auid", &out, "User")
			// Reconstruct CommandLine from execve
			if execve, ok := audit["execve"].(map[string]any); ok {
				var parts []string
				for i := 0; ; i++ {
					key := fmt.Sprintf("a%d", i)
					if v, ok := execve[key].(string); ok {
						parts = append(parts, v)
					} else {
						break
					}
				}
				if len(parts) > 0 {
					out["CommandLine"] = strings.Join(parts, " ")
					highFidelity = true
				}
			}
		}
	}

	// Fallback: extract from full_log (command-output events). This is a text
	// scrape, not a process event, so it is tagged low fidelity.
	if fl, ok := event["full_log"].(string); ok {
		// "ossec: output: 'df -P': ..." → extract command
		if idx := strings.Index(fl, "output: '"); idx >= 0 {
			rest := fl[idx+9:]
			if end := strings.Index(rest, "'"); end > 0 {
				cmd := rest[:end]
				if out["Image"] == "" {
					out["Image"] = cmd
				}
				if out["CommandLine"] == "" {
					out["CommandLine"] = cmd
				}
				lowFidelity = true
			}
		}
	}

	// Use decoder name as fallback Image for SCA events (metadata, low fidelity)
	if out["Image"] == "" {
		if dec, ok := event["decoder"].(map[string]any); ok {
			if name, ok := dec["name"].(string); ok {
				out["Image"] = name
				lowFidelity = true
			}
		}
	}

	switch {
	case highFidelity:
		out[FidelityKey] = FidelityProcess
	case lowFidelity:
		out[FidelityKey] = FidelityLog
	}

	return out
}

func getString(m map[string]any, key string, out *map[string]string, target string) {
	if v, ok := m[key].(string); ok && (*out)[target] == "" {
		(*out)[target] = v
	}
}
