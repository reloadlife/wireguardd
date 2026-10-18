package wgbackend

import (
	"context"
	"strings"
	"testing"
)

func TestRenderMuxSwiftAlias(t *testing.T) {
	got := RenderMux([]MuxMap{{PublicPort: 50310, AWGPort: 50300, Iface: "wg-owire-in", Alias: true}})
	want := `table inet wireguardd_mux {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    fib daddr type local udp dport 50310 counter redirect to :50300 comment "swift alias wg_owire_in"
  }
}
`
	if got != want {
		t.Fatalf("render:\n%s\nwant:\n%s", got, want)
	}
}

func TestRenderMuxGolden(t *testing.T) {
	got := RenderMux([]MuxMap{
		{PublicPort: 51890, AWGPort: 51900, Iface: "awg-het"},
		{PublicPort: 51820, AWGPort: 51830, Iface: "awg0"},
	})
	want := `table inet wireguardd_mux {
  chain prerouting {
    type nat hook prerouting priority dstnat; policy accept;
    fib daddr type local udp dport 51820 jump classify_51820
    fib daddr type local udp dport 51890 jump classify_51890
  }
  chain classify_51820 {
    udp length 156 @th,64,32 0x01000000 counter return comment "wg initiation"
    udp length 100 @th,64,32 0x02000000 counter return comment "wg response"
    udp length 72 @th,64,32 0x03000000 counter return comment "wg cookie"
    udp length >= 40 udp length & 0x000f == 0x0008 @th,64,32 0x04000000 counter return comment "wg transport"
    udp dport 51820 counter redirect to :51830 comment "awg awg0"
  }
  chain classify_51890 {
    udp length 156 @th,64,32 0x01000000 counter return comment "wg initiation"
    udp length 100 @th,64,32 0x02000000 counter return comment "wg response"
    udp length 72 @th,64,32 0x03000000 counter return comment "wg cookie"
    udp length >= 40 udp length & 0x000f == 0x0008 @th,64,32 0x04000000 counter return comment "wg transport"
    udp dport 51890 counter redirect to :51900 comment "awg awg_het"
  }
}
`
	if got != want {
		t.Fatalf("render mismatch:\n%s", got)
	}
	if RenderMux(nil) != "" {
		t.Fatal("empty maps must render nothing")
	}
}

func TestValidateMuxMaps(t *testing.T) {
	bad := [][]MuxMap{
		{{PublicPort: 0, AWGPort: 51830}},
		{{PublicPort: 51820, AWGPort: 51820}},
		{{PublicPort: 51820, AWGPort: 51830}, {PublicPort: 51820, AWGPort: 51840}},
		{{PublicPort: 51820, AWGPort: 51830}, {PublicPort: 51830, AWGPort: 51840}},
	}
	for i, m := range bad {
		if err := ValidateMuxMaps(m); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
	if err := ValidateMuxMaps([]MuxMap{{PublicPort: 51820, AWGPort: 51830}}); err != nil {
		t.Fatal(err)
	}
}

type recRunner struct {
	calls  []string
	listOK bool
}

func (r *recRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	c := name + " " + strings.Join(args, " ")
	r.calls = append(r.calls, c)
	if strings.HasPrefix(c, "nft list table") && !r.listOK {
		return "", errString("no such table")
	}
	if strings.HasPrefix(c, "nft -f") {
		r.listOK = true
	}
	if strings.HasPrefix(c, "nft delete table") {
		r.listOK = false
	}
	return "", nil
}

func TestSyncMuxApplyOnceThenRemove(t *testing.T) {
	r := &recRunner{}
	b := &HostBackend{runner: r}
	maps := []MuxMap{{PublicPort: 51820, AWGPort: 51830, Iface: "awg0"}}
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if err := b.SyncMux(ctx, maps); err != nil {
			t.Fatal(err)
		}
	}
	applies := 0
	for _, c := range r.calls {
		if strings.HasPrefix(c, "nft -f") {
			applies++
		}
	}
	if applies != 1 {
		t.Fatalf("want 1 apply, got %d: %v", applies, r.calls)
	}
	// Table deleted behind our back → re-applied.
	r.listOK = false
	if err := b.SyncMux(ctx, maps); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(r.calls[len(r.calls)-1], "nft -f") {
		t.Fatalf("want re-apply, got %v", r.calls)
	}
	if err := b.SyncMux(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if last := r.calls[len(r.calls)-1]; last != "nft delete table inet wireguardd_mux" {
		t.Fatalf("want delete, got %q", last)
	}
	// Absent + empty → no-op.
	n := len(r.calls)
	if err := b.SyncMux(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != n+1 { // just the list probe
		t.Fatalf("want only list probe, got %v", r.calls[n:])
	}
}
