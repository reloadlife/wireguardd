package reconcile

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/stats"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

func TestReconcileCreatesDeviceAndExports(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	store, err := db.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	backend := wgbackend.NewMock()
	cache := stats.NewCache()
	confDir := t.TempDir()
	r := New(store, backend, cache, Config{
		Persistence:           "hybrid",
		ConfDir:               confDir,
		HandshakeConnectedSec: 180,
	}, slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))

	ctx := context.Background()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	iface := &db.Interface{
		Name:       "wg0",
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
		ListenPort: 51820,
		Addresses:  []string{"10.7.0.1/24"},
		Enabled:    true,
	}
	require.NoError(t, store.CreateInterface(ctx, iface))

	pk, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	peer := &db.Peer{
		InterfaceID: iface.ID,
		PublicKey:   pk.PublicKey,
		Name:        "bob",
		AllowedIPs:  []string{"10.7.0.2/32"},
		AssignedIPs: []string{"10.7.0.2"},
	}
	require.NoError(t, store.CreatePeer(ctx, peer))

	require.NoError(t, r.RunOnce(ctx))

	d, err := backend.Device(ctx, "wg0")
	require.NoError(t, err)
	require.True(t, d.Up)
	require.Len(t, d.Peers, 1)

	confPath := filepath.Join(confDir, "wg0.conf")
	_, err = os.Stat(confPath)
	require.NoError(t, err)

	// traffic limit auto-suspend
	backend.SetPeerTraffic("wg0", pk.PublicKey, 1000, 1000)
	require.NoError(t, r.RunOnce(ctx))
	// set limit and sample again
	p, err := store.GetPeer(ctx, "wg0", pk.PublicKey)
	require.NoError(t, err)
	p.TrafficLimitBytes = 500
	p.LastRxBytes = 1000
	p.LastTxBytes = 1000
	require.NoError(t, store.UpdatePeer(ctx, p))
	require.NoError(t, r.RunOnce(ctx))
	p2, err := store.GetPeer(ctx, "wg0", pk.PublicKey)
	require.NoError(t, err)
	require.True(t, p2.Suspended)

	// allow ticker path compile
	_ = time.Second
}
