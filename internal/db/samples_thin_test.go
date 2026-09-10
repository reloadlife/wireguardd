package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/crypto"
)

func TestThinSamplesKeepsNewestPerBucket(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	iface := &Interface{Name: "wg0", PrivateKey: kp.PrivateKey, PublicKey: kp.PublicKey, Enabled: true}
	require.NoError(t, s.CreateInterface(ctx, iface))
	pk, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	peer := &Peer{InterfaceID: iface.ID, PublicKey: pk.PublicKey, AllowedIPs: []string{"10.0.0.2/32"}}
	require.NoError(t, s.CreatePeer(ctx, peer))

	// 30 minutes of 5s samples = three 10-minute buckets of 120 rows each.
	base := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	samples := make([]TrafficSample, 360)
	for i := range samples {
		samples[i] = TrafficSample{PeerID: peer.ID, SampledAt: base.Add(time.Duration(i) * 5 * time.Second), RxBytes: int64(i)}
	}
	require.NoError(t, s.InsertSamples(ctx, samples))

	n, err := s.ThinSamples(ctx, base, base.Add(20*time.Minute))
	require.NoError(t, err)
	require.Equal(t, int64(238), n)

	list, err := s.ListPeerSamples(ctx, peer.ID, base, base.Add(time.Hour), 1000)
	require.NoError(t, err)
	require.Len(t, list, 122)                     // one per thinned bucket + the untouched third bucket
	require.Equal(t, int64(119), list[0].RxBytes) // newest of the 10:00 bucket
	require.Equal(t, int64(239), list[1].RxBytes) // newest of the 10:10 bucket
	require.Equal(t, int64(240), list[2].RxBytes) // 10:20 is outside [from, to): untouched

	// A second pass over already-thinned data deletes nothing.
	n, err = s.ThinSamples(ctx, base, base.Add(20*time.Minute))
	require.NoError(t, err)
	require.Zero(t, n)
}
