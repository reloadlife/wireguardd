package policy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/db"
)

func TestTrafficLimit(t *testing.T) {
	p := db.Peer{
		LastRxBytes:       1000,
		LastTxBytes:       500,
		RxBytesOffset:     100,
		TxBytesOffset:     0,
		TrafficLimitBytes: 1400,
	}
	require.Equal(t, int64(1400), EffectiveBytes(p))
	require.True(t, TrafficLimitExceeded(p))
	require.True(t, ShouldAutoSuspend(p))

	p.Suspended = true
	require.False(t, ShouldAutoSuspend(p))

	p.Suspended = false
	p.TrafficLimitBytes = 0
	require.False(t, TrafficLimitExceeded(p))
}

func TestExpiresAt(t *testing.T) {
	now := time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)
	p := db.Peer{ExpiresAt: "2026-07-15T11:00:00Z"}
	require.True(t, IsExpired(p, now))
	require.True(t, ShouldAutoSuspendAt(p, now))
	require.Equal(t, "expired", AutoSuspendReason(p, now))

	p.ExpiresAt = "2026-07-15T13:00:00Z"
	require.False(t, IsExpired(p, now))
	require.False(t, ShouldAutoSuspendAt(p, now))

	p.ExpiresAt = ""
	require.False(t, IsExpired(p, now))

	// Already suspended → no auto action.
	p.ExpiresAt = "2020-01-01T00:00:00Z"
	p.Suspended = true
	require.True(t, IsExpired(p, now))
	require.False(t, ShouldAutoSuspendAt(p, now))
	require.Empty(t, AutoSuspendReason(p, now))

	// Invalid timestamp is ignored (not auto-suspended).
	p.Suspended = false
	p.ExpiresAt = "not-a-date"
	require.False(t, IsExpired(p, now))
	require.False(t, ShouldAutoSuspendAt(p, now))
}

func TestExpirePreferredOverTraffic(t *testing.T) {
	now := time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC)
	p := db.Peer{
		LastRxBytes:       100,
		LastTxBytes:       100,
		TrafficLimitBytes: 50,
		ExpiresAt:         "2026-01-01T00:00:00Z",
	}
	require.Equal(t, "expired", AutoSuspendReason(p, now))
	require.True(t, ShouldAutoSuspendAt(p, now))
}

func TestEffectiveBandwidth(t *testing.T) {
	// Total alone → both directions.
	rx, tx := EffectiveBandwidth(0, 0, 1_000_000)
	require.Equal(t, int64(1_000_000), rx)
	require.Equal(t, int64(1_000_000), tx)

	// Explicit rx/tx win over total.
	rx, tx = EffectiveBandwidth(100, 200, 1_000_000)
	require.Equal(t, int64(100), rx)
	require.Equal(t, int64(200), tx)

	// Fill only zero directions from total.
	rx, tx = EffectiveBandwidth(500, 0, 1_000_000)
	require.Equal(t, int64(500), rx)
	require.Equal(t, int64(1_000_000), tx)

	rx, tx = EffectiveBandwidth(0, 300, 1_000_000)
	require.Equal(t, int64(1_000_000), rx)
	require.Equal(t, int64(300), tx)

	// No total → leave as-is.
	rx, tx = EffectiveBandwidth(10, 0, 0)
	require.Equal(t, int64(10), rx)
	require.Equal(t, int64(0), tx)
}
