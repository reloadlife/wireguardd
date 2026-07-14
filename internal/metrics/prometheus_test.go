package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/stats"
)

func TestCollectorRegisters(t *testing.T) {
	reg := prometheus.NewRegistry()
	cache := stats.NewCache()
	cache.SetInterface(stats.IfaceStats{Name: "wg0", Up: true, PeerCount: 1, ListenPort: 51820})
	cache.SetPeer(stats.PeerStats{
		Interface: "wg0", PublicKey: "abc", Name: "p", Connected: true,
		RxBytes: 10, TxBytes: 20, UpdatedAt: time.Now(),
	})
	_ = New(cache, reg)
	mfs, err := reg.Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs)
}
