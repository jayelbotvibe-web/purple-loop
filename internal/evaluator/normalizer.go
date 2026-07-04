package evaluator

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Normalizer maps Wazuh event JSON to canonical Sigma field names.
// ponytail: derived from real captured events, not memory.
type Normalizer struct{}

// Normalize converts a raw Wazuh event into a flat map of canonical fields.
func (Normalizer) Normalize(raw json.RawMessage) map[string]string {
	var event map[string]any
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil
	}
	out := make(map[string]string)

	// Top-level canonical fields (dry-run, fixtures)
	getString(event, "Image", &out, "Image")
	getString(event, "ParentImage", &out, "ParentImage")
	getString(event, "CommandLine", &out, "CommandLine")
	getString(event, "User", &out, "User")

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
				}
			}
		}
	}

	// Fallback: extract from full_log (command output events)
	if fl, ok := event["full_log"].(string); ok {
		// "ossec: output: 'df -P': ..." → extract command
		if idx := strings.Index(fl, "output: '"); idx >= 0 {
			rest := fl[idx+9:]
			if end := strings.Index(rest, "'"); end > 0 {
				cmd := rest[:end]
				out["Image"] = cmd
				out["CommandLine"] = cmd
			}
		}
	}

	// Use decoder name as fallback Image for SCA events
	if out["Image"] == "" {
		if dec, ok := event["decoder"].(map[string]any); ok {
			if name, ok := dec["name"].(string); ok {
				out["Image"] = name
			}
		}
	}

	return out
}

func getString(m map[string]any, key string, out *map[string]string, target string) {
	if v, ok := m[key].(string); ok && (*out)[target] == "" {
		(*out)[target] = v
	}
}
