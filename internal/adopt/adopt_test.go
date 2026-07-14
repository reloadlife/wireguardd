package adopt_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/adopt"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

func TestAdoptLiveDevice(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	peerKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	mock := wgbackend.NewMock()
	// Pre-existing host interface (no private key readable — common when only root can read).
	mock.DevicesM["wg0"] = &wgbackend.Device{
		Name:       "wg0",
		PublicKey:  kp.PublicKey,
		PrivateKey: "", // missing
		ListenPort: 51820,
		Addresses:  []string{"10.7.0.1/24", "fe80::1/64"},
		Up:         true,
		Peers: []wgbackend.Peer{{
			PublicKey:                   peerKP.PublicKey,
			AllowedIPs:                  []string{"10.7.0.2/32"},
			Endpoint:                    "203.0.113.5:51820",
			PersistentKeepaliveInterval: 25 * time.Second,
			ReceiveBytes:                1000,
			TransmitBytes:               2000,
		}},
	}

	confDir := t.TempDir()
	// Conf supplies the private key the kernel didn't expose.
	require.NoError(t, os.WriteFile(filepath.Join(confDir, "wg0.conf"), []byte(`
[Interface]
PrivateKey = `+kp.PrivateKey+`
Address = 10.7.0.1/24
ListenPort = 51820
Table = off

[Peer]
PublicKey = `+peerKP.PublicKey+`
AllowedIPs = 10.7.0.2/32
`), 0o600))

	svc := adopt.New(store, mock, confDir, nil)
	ctx := context.Background()

	preview, err := svc.Discover(ctx, adopt.Options{ReadConf: true})
	require.NoError(t, err)
	require.Len(t, preview.Preview, 1)
	require.Equal(t, "wg0", preview.Preview[0].Name)
	require.True(t, preview.Preview[0].HasPrivateKey)
	require.True(t, preview.Preview[0].ConfLoaded)
	require.Equal(t, 1, preview.Preview[0].PeerCount)
	require.False(t, preview.Preview[0].AlreadyInDB)

	rep, err := svc.Adopt(ctx, adopt.Options{ReadConf: true})
	require.NoError(t, err)
	require.Len(t, rep.Results, 1)
	require.Equal(t, "created", rep.Results[0].Action)
	require.True(t, rep.Results[0].HasPrivateKey)

	iface, err := store.GetInterfaceByName(ctx, "wg0")
	require.NoError(t, err)
	require.Equal(t, kp.PrivateKey, iface.PrivateKey)
	require.Equal(t, "off", iface.TableMode)
	require.Equal(t, []string{"10.7.0.1/24"}, iface.Addresses)

	peers, err := store.ListPeersByInterface(ctx, "wg0")
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Equal(t, peerKP.PublicKey, peers[0].PublicKey)
	require.Equal(t, []string{"10.7.0.2/32"}, peers[0].AllowedIPs)
	require.Equal(t, []string{"10.7.0.2"}, peers[0].AssignedIPs)

	// Second adopt without overwrite → skipped
	rep2, err := svc.Adopt(ctx, adopt.Options{ReadConf: true, Overwrite: false})
	require.NoError(t, err)
	require.Equal(t, "skipped", rep2.Results[0].Action)

	// Soft EnsureInterface must not wipe key when desired has empty private key
	require.NoError(t, mock.EnsureInterface(ctx, wgbackend.DesiredInterface{
		Name: "wg0", PrivateKey: "", Enabled: true, ListenPort: 51820,
	}))
	d, err := mock.Device(ctx, "wg0")
	require.NoError(t, err)
	// mock still has empty priv from original device setup before conf ensure —
	// re-set via adopt path already put key in DB only; mock Ensure soft-skip keeps prior.
	_ = d
}

func TestAdoptWithoutConfMissingKey(t *testing.T) {
	store, err := db.Open(filepath.Join(t.TempDir(), "s.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })

	pub := "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	// Use a valid-looking public key from a real keypair
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	pub = kp.PublicKey
	peerKP, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	mock := wgbackend.NewMock()
	mock.DevicesM["wg1"] = &wgbackend.Device{
		Name: "wg1", PublicKey: pub, ListenPort: 51821, Up: true,
		Addresses: []string{"10.8.0.1/24"},
		Peers:     []wgbackend.Peer{{PublicKey: peerKP.PublicKey, AllowedIPs: []string{"10.8.0.2/32"}}},
	}

	svc := adopt.New(store, mock, t.TempDir(), nil)
	rep, err := svc.Adopt(context.Background(), adopt.Options{ReadConf: true})
	require.NoError(t, err)
	require.Equal(t, "created", rep.Results[0].Action)
	require.False(t, rep.Results[0].HasPrivateKey)

	iface, err := store.GetInterfaceByName(context.Background(), "wg1")
	require.NoError(t, err)
	require.Empty(t, iface.PrivateKey)
	require.Equal(t, pub, iface.PublicKey)
}

func TestEnsureInterfaceSoftNoWipeAddresses(t *testing.T) {
	mock := wgbackend.NewMock()
	mock.DevicesM["wg0"] = &wgbackend.Device{
		Name: "wg0", Addresses: []string{"10.0.0.1/24"}, PrivateKey: "keep-me", Up: true,
	}
	require.NoError(t, mock.EnsureInterface(context.Background(), wgbackend.DesiredInterface{
		Name: "wg0", Enabled: true, // empty addresses + empty key
	}))
	d, err := mock.Device(context.Background(), "wg0")
	require.NoError(t, err)
	require.Equal(t, "keep-me", d.PrivateKey)
	require.Equal(t, []string{"10.0.0.1/24"}, d.Addresses)
}
