package wgbackend

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMockBackendLifecycle(t *testing.T) {
	m := NewMock()
	ctx := context.Background()
	err := m.EnsureInterface(ctx, DesiredInterface{
		Name:       "wg0",
		PrivateKey: "x",
		ListenPort: 51820,
		Enabled:    true,
	})
	require.NoError(t, err)
	devs, err := m.Devices(ctx)
	require.NoError(t, err)
	require.Len(t, devs, 1)

	err = m.ApplyPeers(ctx, "wg0", []DesiredPeer{{
		PublicKey:  "peer1",
		AllowedIPs: []string{"10.0.0.2/32"},
	}})
	require.NoError(t, err)
	d, err := m.Device(ctx, "wg0")
	require.NoError(t, err)
	require.Len(t, d.Peers, 1)
	require.Equal(t, []string{"10.0.0.2/32"}, d.Peers[0].AllowedIPs)

	m.SetPeerTraffic("wg0", "peer1", 999, 888)
	err = m.ApplyPeers(ctx, "wg0", []DesiredPeer{{
		PublicKey:  "peer1",
		AllowedIPs: []string{"10.0.0.2/32"},
		Suspended:  true,
	}})
	require.NoError(t, err)
	d, err = m.Device(ctx, "wg0")
	require.NoError(t, err)
	require.Empty(t, d.Peers[0].AllowedIPs)
	require.Equal(t, int64(999), d.Peers[0].ReceiveBytes)
	require.Equal(t, int64(888), d.Peers[0].TransmitBytes)

	path := filepath.Join(t.TempDir(), "wg0.conf")
	require.NoError(t, m.ExportConf(ctx, path, "test"))
	require.Equal(t, "test", m.Exports[path])

	require.NoError(t, m.RemoveInterface(ctx, "wg0"))
	devs, err = m.Devices(ctx)
	require.NoError(t, err)
	require.Empty(t, devs)
}
