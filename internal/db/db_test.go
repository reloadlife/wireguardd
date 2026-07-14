package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/crypto"
)

func openTestDB(t *testing.T) *Store {
	t.Helper()
	// Unique memory DB per test via file path in temp.
	path := t.TempDir() + "/test.db"
	s, err := Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestInterfaceAndPeerCRUD(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)

	iface := &Interface{
		Name:       "wg0",
		PrivateKey: kp.PrivateKey,
		PublicKey:  kp.PublicKey,
		ListenPort: 51820,
		Addresses:  []string{"10.0.0.1/24", "fd00::1/64"},
		DNS:        []string{"1.1.1.1"},
		Enabled:    true,
	}
	require.NoError(t, s.CreateInterface(ctx, iface))
	require.NotZero(t, iface.ID)

	got, err := s.GetInterfaceByName(ctx, "wg0")
	require.NoError(t, err)
	require.Equal(t, "wg0", got.Name)
	require.Equal(t, []string{"10.0.0.1/24", "fd00::1/64"}, got.Addresses)

	pk, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	peer := &Peer{
		InterfaceID: iface.ID,
		PublicKey:   pk.PublicKey,
		Name:        "alice",
		AllowedIPs:  []string{"10.0.0.2/32"},
		AssignedIPs: []string{"10.0.0.2"},
	}
	require.NoError(t, s.CreatePeer(ctx, peer))

	peers, err := s.ListPeersByInterface(ctx, "wg0")
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Equal(t, "alice", peers[0].Name)

	require.NoError(t, s.SetPeerSuspended(ctx, peer.ID, true))
	p2, err := s.GetPeer(ctx, "wg0", pk.PublicKey)
	require.NoError(t, err)
	require.True(t, p2.Suspended)

	require.NoError(t, s.SoftResetPeerTraffic(ctx, peer.ID, 100, 200))
	p3, err := s.GetPeer(ctx, "wg0", pk.PublicKey)
	require.NoError(t, err)
	require.Equal(t, int64(100), p3.RxBytesOffset)
	require.Equal(t, int64(200), p3.TxBytesOffset)

	require.NoError(t, s.AddEvent(ctx, "info", "audit", "wg0", pk.PublicKey, "created", `{}`))
	ev, err := s.ListEvents(ctx, 10)
	require.NoError(t, err)
	require.Len(t, ev, 1)

	// Atomic import replaces peer set in one transaction.
	pk2, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	require.NoError(t, s.ImportInterface(ctx, iface, []Peer{
		{PublicKey: pk2.PublicKey, Name: "bob", AllowedIPs: []string{"10.0.0.3/32"}},
	}))
	peers, err = s.ListPeersByInterface(ctx, "wg0")
	require.NoError(t, err)
	require.Len(t, peers, 1)
	require.Equal(t, "bob", peers[0].Name)
	require.Equal(t, pk2.PublicKey, peers[0].PublicKey)

	require.NoError(t, s.DeletePeer(ctx, "wg0", pk2.PublicKey))
	require.NoError(t, s.DeleteInterface(ctx, "wg0"))
	_, err = s.GetInterfaceByName(ctx, "wg0")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestTrafficSamplesAndWindows(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	iface := &Interface{Name: "wg0", PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, Enabled: true}
	require.NoError(t, s.CreateInterface(ctx, iface))
	pk, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	peer := &Peer{InterfaceID: iface.ID, PublicKey: pk.PublicKey, Name: "alice", AllowedIPs: []string{"10.0.0.2/32"}}
	require.NoError(t, s.CreatePeer(ctx, peer))

	now := time.Now().UTC().Truncate(time.Second)
	require.NoError(t, s.InsertSample(ctx, TrafficSample{
		PeerID: peer.ID, SampledAt: now.Add(-10 * time.Minute), RxBytes: 1000, TxBytes: 500, RxBps: 10, TxBps: 5,
	}))
	require.NoError(t, s.InsertSample(ctx, TrafficSample{
		PeerID: peer.ID, SampledAt: now.Add(-2 * time.Minute), RxBytes: 5000, TxBytes: 2500, RxBps: 50, TxBps: 25,
	}))
	require.NoError(t, s.InsertSample(ctx, TrafficSample{
		PeerID: peer.ID, SampledAt: now, RxBytes: 9000, TxBytes: 4000, RxBps: 80, TxBps: 40,
	}))

	base, err := s.SampleAtOrBefore(ctx, peer.ID, now.Add(-5*time.Minute))
	require.NoError(t, err)
	require.Equal(t, int64(1000), base.RxBytes) // 10m sample is at-or-before 5m cutoff

	bases, err := s.PeerWindowBaselines(ctx, peer.ID, map[string]time.Time{
		"1m":  now.Add(-time.Minute),
		"15m": now.Add(-15 * time.Minute),
	})
	require.NoError(t, err)
	require.Equal(t, int64(5000), bases["1m"].RxBytes) // 2m sample
	_, has15 := bases["15m"]
	require.False(t, has15, "no sample older than 15m")

	list, err := s.ListPeerSamples(ctx, peer.ID, now.Add(-15*time.Minute), now, 100)
	require.NoError(t, err)
	require.Len(t, list, 3)
}
