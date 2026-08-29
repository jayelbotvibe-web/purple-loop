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

	// Try Windows Sysmon / EventChannel paths.
	//
	// CRITICAL: only genuine PROCESS-CREATION events (Sysmon EventID 1, Security
	// 4688) may be tagged high fidelity. Other Windows events (network
	// connection=3, account enumeration=4798, handle=4656, …) also carry a
	// process name (callerProcessName/processName) but are NOT proof a process
	// was created. Tagging them as process telemetry credited a process-creation
	// detection off an enumeration/network event — a false DETECTED.
	if data, ok := event["data"].(map[string]any); ok {
		if win, ok := data["win"].(map[string]any); ok {
			if ed, ok := win["eventdata"].(map[string]any); ok {
				eventID := winEventID(win)
				if eventID != "" {
					out["EventID"] = eventID
				}
				if isProcessCreation(ed, eventID) {
					// Real process creation — its fields are evidence.
					getString(ed, "image", &out, "Image")
					getString(ed, "parentImage", &out, "ParentImage")
					getString(ed, "commandLine", &out, "CommandLine")
					getString(ed, "user", &out, "User")
					getString(ed, "parentUser", &out, "User")
					getString(ed, "newProcessName", &out, "Image") // Security 4688
					getString(ed, "parentProcessName", &out, "ParentImage")
					getString(ed, "subjectUserName", &out, "User")
					highFidelity = true
				} else {
					// Non-creation event: extract for context only, LOW fidelity,
					// so process_creation rules can never match it.
					getString(ed, "image", &out, "Image")
					getString(ed, "callerProcessName", &out, "Image")
					getString(ed, "processName", &out, "Image")
					getString(ed, "commandLine", &out, "CommandLine")
					getString(ed, "user", &out, "User")
					getString(ed, "subjectUserName", &out, "User")
					if out["Image"] != "" || out["CommandLine"] != "" {
						lowFidelity = true
					}
				}
			}
		}
	}

	// Try Linux-Sysmon (eBPF) paths.
	//
	// Sysmon for Linux emits the same process-creation semantics as its Windows
	// counterpart — EventID 1 with Image, CommandLine, ParentImage, User — but it
	// is NOT an eventchannel event, so it gets its own path rather than being
	// smuggled through data.win. The same gate applies: only EventID 1 is
	// process creation, and only process creation is high fidelity.
	if data, ok := event["data"].(map[string]any); ok {
		if sm, ok := data["sysmon"].(map[string]any); ok {
			eventID := anyToString(sm["eventID"])
			if eventID != "" {
				out["EventID"] = eventID
			}
			if eventID == "1" {
				getString(sm, "image", &out, "Image")
				getString(sm, "parentImage", &out, "ParentImage")
				getString(sm, "commandLine", &out, "CommandLine")
				getString(sm, "user", &out, "User")
				highFidelity = true
			} else {
				// Any other Sysmon event (network, file, …) carries a process
				// name without being proof a process was created.
				getString(sm, "image", &out, "Image")
				getString(sm, "commandLine", &out, "CommandLine")
				getString(sm, "user", &out, "User")
				if out["Image"] != "" || out["CommandLine"] != "" {
					lowFidelity = true
				}
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

// isProcessCreation reports whether a Windows eventdata block is genuine
// process-creation telemetry: Sysmon EventID 1 / Security 4688, or — when the
// structured EventID is absent (as in some captured events) — the
// process-creation field signature (a command line plus an image/new-process
// name). Enumeration/network events (callerProcessName only, no command line)
// are correctly excluded.
func isProcessCreation(ed map[string]any, eventID string) bool {
	if eventID == "1" || eventID == "4688" {
		return true
	}
	return nonEmptyStr(ed, "commandLine") && (nonEmptyStr(ed, "image") || nonEmptyStr(ed, "newProcessName"))
}

func nonEmptyStr(m map[string]any, key string) bool {
	s, ok := m[key].(string)
	return ok && s != ""
}

// anyToString renders a JSON value that may be a string or a number.
func anyToString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%d", int(t))
	}
	return ""
}

// winEventID extracts data.win.system.eventID (string or numeric) or "".
func winEventID(win map[string]any) string {
	sys, ok := win["system"].(map[string]any)
	if !ok {
		return ""
	}
	switch v := sys["eventID"].(type) {
	case string:
		return v
	case float64:
		return fmt.Sprintf("%d", int(v))
	}
	return ""
}

func getString(m map[string]any, key string, out *map[string]string, target string) {
	if v, ok := m[key].(string); ok && (*out)[target] == "" {
		(*out)[target] = v
	}
}
