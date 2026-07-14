package stats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestComputeRate(t *testing.T) {
	t0 := time.Unix(0, 0).UTC()
	t1 := t0.Add(2 * time.Second)
	r := ComputeRate(Sample{Time: t0, Rx: 100, Tx: 50}, Sample{Time: t1, Rx: 300, Tx: 150})
	require.InDelta(t, 100, r.RxBps, 0.01)
	require.InDelta(t, 50, r.TxBps, 0.01)

	// reset
	r = ComputeRate(Sample{Time: t0, Rx: 500, Tx: 50}, Sample{Time: t1, Rx: 10, Tx: 150})
	require.Equal(t, 0.0, r.RxBps)
	require.InDelta(t, 50, r.TxBps, 0.01)
}

func TestEWMA(t *testing.T) {
	v := EWMA(100, 0, 0.5)
	require.InDelta(t, 50, v, 0.01)
}
