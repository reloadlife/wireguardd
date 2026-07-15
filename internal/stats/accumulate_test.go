package stats

import "testing"

func TestAccumulateLifetime(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name                string
		lifetime, raw, prev int64
		hasPrev             bool
		want                int64
	}{
		{name: "cold start", lifetime: 0, raw: 1000, hasPrev: false, want: 1000},
		{name: "continued after daemon restart", lifetime: 5000, raw: 5200, hasPrev: false, want: 5200},
		{name: "reboot preserves lifetime", lifetime: 5000, raw: 100, hasPrev: false, want: 5000},
		{name: "normal growth", lifetime: 5000, raw: 1100, prev: 1000, hasPrev: true, want: 5100},
		{name: "mid-process reset", lifetime: 5000, raw: 200, prev: 1000, hasPrev: true, want: 5200},
		{name: "zero after reset", lifetime: 5000, raw: 0, prev: 1000, hasPrev: true, want: 5000},
		{name: "no change", lifetime: 5000, raw: 1000, prev: 1000, hasPrev: true, want: 5000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := AccumulateLifetime(tc.lifetime, tc.raw, tc.prev, tc.hasPrev)
			if got != tc.want {
				t.Fatalf("got %d want %d", got, tc.want)
			}
		})
	}
}
