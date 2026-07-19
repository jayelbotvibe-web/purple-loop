package evaluator

import "testing"

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		name      string
		value     string // the candidate value (from the rule, may contain *)
		eventVal  string // the event field value
		modifiers []string
		want      bool
	}{
		// Suffix wildcards
		{name: "suffix wildcard", value: `*\net.exe`, eventVal: `C:\Windows\System32\net.exe`, want: true},
		{name: "suffix wildcard no match", value: `*\net.exe`, eventVal: `C:\Windows\System32\net1.exe`, want: false},
		// Prefix wildcards
		{name: "prefix wildcard", value: `C:\Windows\*`, eventVal: `C:\Windows\System32\net.exe`, want: true},
		{name: "prefix wildcard no match", value: `C:\Windows\*`, eventVal: `D:\Windows\System32\net.exe`, want: false},
		// Contains wildcards
		{name: "contains wildcard", value: `*\System32\*`, eventVal: `C:\Windows\System32\net.exe`, want: true},
		{name: "contains wildcard no match", value: `*\System32\*`, eventVal: `C:\Windows\SysWOW64\net.exe`, want: false},
		// Both ends
		{name: "both wildcards", value: `*\System32\*`, eventVal: `C:\Windows\System32\net.exe`, want: true},
		// Multi-segment
		{name: "multi wildcard", value: `*Windows*\net.exe`, eventVal: `C:\Windows\System32\net.exe`, want: true},
		{name: "multi wildcard no match", value: `*Win*\net.exe`, eventVal: `C:\Windows\System32\net1.exe`, want: false},
		// Asterisk-only
		{name: "star only matches everything", value: `*`, eventVal: `anything`, want: true},
		// Literal (no wildcard)
		{name: "literal match", value: `C:\Windows\System32\net.exe`, eventVal: `C:\Windows\System32\net.exe`, want: true},
		{name: "literal no match", value: `C:\Windows\System32\net.exe`, eventVal: `C:\Windows\System32\net1.exe`, want: false},
		// Wildcard with contains modifier — wildcard should work with modifiers
		{name: "wildcard + contains", value: `*\net.exe`, eventVal: `c:\windows\system32\NET.EXE`, modifiers: []string{"contains"}, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			entry := FieldEntry{Values: []string{tt.value}, Modifiers: tt.modifiers}
			got := matchField(tt.eventVal, entry)
			if got != tt.want {
				t.Errorf("matchField(%q, {%q, %v}) = %v, want %v",
					tt.eventVal, tt.value, tt.modifiers, got, tt.want)
			}
		})
	}
}
