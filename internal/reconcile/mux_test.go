package reconcile

import (
	"testing"

	"github.com/reloadlife/wireguardd/internal/db"
)

func TestMuxMaps(t *testing.T) {
	noisy := `{"s1":20,"s2":40,"h1":"123","h2":"456","h3":"789","h4":"1011"}`
	ifaces := []db.Interface{
		{Name: "wg0", Protocol: "wg", ListenPort: 51820, Enabled: true},
		{Name: "awg0", Protocol: "awg", ListenPort: 51830, MuxPort: 51820, Enabled: true, AmneziaJSON: noisy},
		{Name: "awg-off", Protocol: "awg", ListenPort: 51840, MuxPort: 51821, Enabled: false, AmneziaJSON: noisy},
		{Name: "awg-neutral", Protocol: "awg", ListenPort: 51850, MuxPort: 51822, Enabled: true, AmneziaJSON: `{"h1":"1","h2":"2","h3":"3","h4":"4"}`},
		{Name: "awg-nomux", Protocol: "awg", ListenPort: 51860, Enabled: true, AmneziaJSON: noisy},
	}
	maps, skipped := muxMaps(ifaces)
	if len(maps) != 1 || maps[0].PublicPort != 51820 || maps[0].AWGPort != 51830 || maps[0].Iface != "awg0" {
		t.Fatalf("maps = %+v", maps)
	}
	if len(skipped) != 1 {
		t.Fatalf("skipped = %v", skipped)
	}
}
