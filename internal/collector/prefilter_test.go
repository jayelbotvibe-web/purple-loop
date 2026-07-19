package collector

import (
	"testing"
	"time"

	"github.com/jayelbotvibe-web/purple-loop/internal/model"
)

func TestDateAlternation(t *testing.T) {
	mk := func(s, e string) model.TimeWindow {
		start, _ := time.Parse(time.RFC3339, s)
		end, _ := time.Parse(time.RFC3339, e)
		return model.TimeWindow{Start: start, End: end}
	}

	cases := []struct {
		name string
		w    model.TimeWindow
		want string
	}{
		{"same day", mk("2026-07-04T09:00:00Z", "2026-07-04T09:05:00Z"), "2026-07-04"},
		{"spans midnight", mk("2026-07-04T23:59:00Z", "2026-07-05T00:02:00Z"), "2026-07-04|2026-07-05"},
		{"zero window", model.TimeWindow{}, ""},
		{"reversed", mk("2026-07-05T00:00:00Z", "2026-07-04T00:00:00Z"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := dateAlternation(c.w); got != c.want {
				t.Errorf("dateAlternation = %q, want %q", got, c.want)
			}
		})
	}
}

func TestShQuote(t *testing.T) {
	if got := shQuote("victim01"); got != "'victim01'" {
		t.Errorf("shQuote = %q", got)
	}
	// An embedded single quote must be escaped so it cannot break out.
	if got := shQuote("a'b"); got != `'a'\''b'` {
		t.Errorf("shQuote escaping = %q", got)
	}
}
