package collector

import (
	"testing"
	"time"
)

func TestParseTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		want    time.Time // expected truncated result (time.UTC)
	}{
		{
			name:    "wazuh archives (ms fraction + numeric offset)",
			input:   "2026-07-04T10:37:28.086+0000",
			wantErr: false,
			want:    time.Date(2026, 7, 4, 10, 37, 28, 86_000_000, time.UTC),
		},
		{
			name:    "RFC3339 with Z suffix",
			input:   "2026-07-04T10:37:28Z",
			wantErr: false,
			want:    time.Date(2026, 7, 4, 10, 37, 28, 0, time.UTC),
		},
		{
			name:    "RFC3339Nano with Z suffix",
			input:   "2026-07-04T10:37:28.086Z",
			wantErr: false,
			want:    time.Date(2026, 7, 4, 10, 37, 28, 86_000_000, time.UTC),
		},
		{
			name:    "no fraction + numeric offset",
			input:   "2026-07-04T10:37:28+0000",
			wantErr: false,
			want:    time.Date(2026, 7, 4, 10, 37, 28, 0, time.UTC),
		},
		{
			name:    "RFC3339Nano with colon offset",
			input:   "2026-07-04T10:37:28.086+00:00",
			wantErr: false,
			want:    time.Date(2026, 7, 4, 10, 37, 28, 86_000_000, time.FixedZone("", 0)),
		},
		{
			name:    "garbage",
			input:   "not-a-timestamp",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTimestamp(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !got.Equal(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseTimestamp_WindowMatch(t *testing.T) {
	// Verify parsed timestamps land inside a reasonable window and are not zero.
	ts := "2026-07-04T10:37:28.086+0000"
	got, err := parseTimestamp(ts)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.IsZero() {
		t.Error("timestamp is zero (would be dropped)")
	}
	windowStart := time.Date(2026, 7, 4, 10, 37, 0, 0, time.UTC)
	windowEnd := time.Date(2026, 7, 4, 10, 38, 0, 0, time.UTC)
	if got.Before(windowStart) || got.After(windowEnd) {
		t.Errorf("timestamp %v outside expected window [%v, %v]", got, windowStart, windowEnd)
	}
}
