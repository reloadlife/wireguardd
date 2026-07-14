package wgbackend

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeTableMode(t *testing.T) {
	require.Equal(t, tableModeAuto, normalizeTableMode(""))
	require.Equal(t, tableModeAuto, normalizeTableMode("auto"))
	require.Equal(t, tableModeOff, normalizeTableMode("off"))
	require.Equal(t, tableModeNumber, normalizeTableMode("number"))
	require.Equal(t, tableModeNumber, normalizeTableMode("51820"))
}

func TestResolveTableID(t *testing.T) {
	id := 100
	s, n := ResolveTableID("number", &id)
	require.Equal(t, "100", s)
	require.Equal(t, 100, n)
	s, _ = ResolveTableID("off", nil)
	require.Equal(t, "off", s)
	s, _ = ResolveTableID("auto", nil)
	require.Equal(t, "auto", s)
}

func TestClassifyCIDR(t *testing.T) {
	p, def, err := classifyCIDR("0.0.0.0/0")
	require.NoError(t, err)
	require.Equal(t, "4", p)
	require.True(t, def)

	p, def, err = classifyCIDR("::/0")
	require.NoError(t, err)
	require.Equal(t, "6", p)
	require.True(t, def)

	p, def, err = classifyCIDR("10.0.0.0/24")
	require.NoError(t, err)
	require.Equal(t, "4", p)
	require.False(t, def)
}

func TestSyncRoutesAuto(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, routes: newRouteState()}
	ctx := context.Background()
	err := b.SyncRoutes(ctx, DesiredInterface{
		Name:      "wg0",
		TableMode: "auto",
		Enabled:   true,
		Peers: []DesiredPeer{{
			PublicKey:  "p1",
			AllowedIPs: []string{"10.0.0.0/24", "192.168.1.0/24"},
		}},
	})
	require.NoError(t, err)
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "ip -4 route replace 10.0.0.0/24 dev wg0")
	require.Contains(t, joined, "ip -4 route replace 192.168.1.0/24 dev wg0")
	// main table routes have no explicit table keyword
	require.NotContains(t, joined, "table 10.0.0.0")
}

func TestSyncRoutesOff(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, routes: newRouteState()}
	ctx := context.Background()
	// first install
	require.NoError(t, b.SyncRoutes(ctx, DesiredInterface{
		Name: "wg0", TableMode: "auto", Enabled: true,
		Peers: []DesiredPeer{{AllowedIPs: []string{"10.0.0.0/24"}}},
	}))
	// then off
	require.NoError(t, b.SyncRoutes(ctx, DesiredInterface{
		Name: "wg0", TableMode: "off", Enabled: true,
		Peers: []DesiredPeer{{AllowedIPs: []string{"10.0.0.0/24"}}},
	}))
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "route del 10.0.0.0/24")
}

func TestSyncRoutesCustomTable(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, routes: newRouteState()}
	ctx := context.Background()
	tid := 100
	err := b.SyncRoutes(ctx, DesiredInterface{
		Name: "wg0", TableMode: "number", TableID: &tid, Enabled: true,
		Addresses: []string{"10.7.0.1/24", "fd00::1/64"},
		Peers: []DesiredPeer{{
			AllowedIPs: []string{"10.0.0.0/8", "fd00:1::/64"},
		}},
	})
	require.NoError(t, err)
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "table 100")
	require.Contains(t, joined, "from 10.7.0.1 lookup 100")
	require.Contains(t, joined, "from fd00::1 lookup 100")
	require.Contains(t, joined, "iif wg0 lookup 100")
}

func TestSyncRoutesDefaultAuto(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, routes: newRouteState(), bandwidthBackend: "none"}
	ctx := context.Background()
	err := b.SyncRoutes(ctx, DesiredInterface{
		Name: "wg0", TableMode: "auto", ListenPort: 51820, Enabled: true,
		Peers: []DesiredPeer{{
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	})
	require.NoError(t, err)
	joined := strings.Join(rec.joined(), "\n")
	// default routes go to special table = listen port
	require.Contains(t, joined, "0.0.0.0/0 dev wg0 table 51820")
	require.Contains(t, joined, "::/0 dev wg0 table 51820")
	require.Contains(t, joined, "fwmark 0xca6c") // 51820 = 0xca6c
	require.Contains(t, joined, "suppress_prefixlength 0")
}

func TestSyncRoutesSkipsSuspended(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, routes: newRouteState()}
	ctx := context.Background()
	require.NoError(t, b.SyncRoutes(ctx, DesiredInterface{
		Name: "wg0", TableMode: "auto", Enabled: true,
		Peers: []DesiredPeer{{
			AllowedIPs: []string{"10.0.0.0/24"},
			Suspended:  true,
		}},
	}))
	require.Empty(t, rec.cmds)
}

func TestMockSyncRoutes(t *testing.T) {
	m := NewMock()
	tid := 50
	require.NoError(t, m.SyncRoutes(context.Background(), DesiredInterface{
		Name: "wg0", TableMode: "number", TableID: &tid, Enabled: true,
		Peers: []DesiredPeer{{AllowedIPs: []string{"10.0.0.0/24", "10.1.0.0/24"}}},
	}))
	require.Equal(t, "50", m.RouteTables["wg0"])
	require.Equal(t, 2, m.RouteCounts["wg0"])
}
