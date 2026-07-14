package policy

import (
	"testing"

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
