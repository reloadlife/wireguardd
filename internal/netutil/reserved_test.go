package netutil

import "testing"

func TestReservedHostInterface(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"mesh0", true},
		{"mesh1", true},
		{"mesh-cp", true},
		{"MESH0", false}, // kernel names are case-sensitive; we only guard lowercase ops names
		{"wg-owire-in", false},
		{"wg-owire-awg", false},
		{"wg0", false},
		{"", false},
		{"  mesh0  ", true},
	}
	for _, tc := range cases {
		if got := ReservedHostInterface(tc.name); got != tc.want {
			t.Fatalf("ReservedHostInterface(%q)=%v want %v", tc.name, got, tc.want)
		}
	}
}
