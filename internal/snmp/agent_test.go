package snmp

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/stats"
)

func TestOIDCompare(t *testing.T) {
	a := parseOID("1.3.6.1")
	b := parseOID("1.3.6.1.4")
	require.Equal(t, -1, a.Compare(b))
	require.True(t, a.IsPrefix(b))
	require.Equal(t, "1.3.6.1.4", a.Child(4).String())
}

func TestSnapshotVars(t *testing.T) {
	cache := stats.NewCache()
	cache.SetInterface(stats.IfaceStats{Name: "wg0", Up: true, ListenPort: 51820, PeerCount: 1, RxBytes: 10})
	cache.SetPeer(stats.PeerStats{Interface: "wg0", PublicKey: "pk", Name: "n", RxBytes: 5, Connected: true})
	a := NewAgent("127.0.0.1:0", "public", "1.3.6.1.4.1.66666.1", cache, nil)
	vars := a.snapshotVars()
	require.NotEmpty(t, vars)
}
