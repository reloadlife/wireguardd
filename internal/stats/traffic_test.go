package stats

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWindowDelta(t *testing.T) {
	w := WindowDelta(1000, 500, 200, 100, time.Minute)
	require.Equal(t, int64(800), w.RxBytes)
	require.Equal(t, int64(400), w.TxBytes)
	require.InDelta(t, 800.0/60.0, w.RxBpsAvg, 0.01)
	require.InDelta(t, 400.0/60.0, w.TxBpsAvg, 0.01)
}

func TestWindowDeltaSoftReset(t *testing.T) {
	// current below baseline after soft-reset → use current as window total
	w := WindowDelta(50, 10, 1000, 500, time.Minute)
	require.Equal(t, int64(50), w.RxBytes)
	require.Equal(t, int64(10), w.TxBytes)
}

func TestBuildTraffic(t *testing.T) {
	tr := BuildTraffic(100, 200, Rates{RxBps: 1.5, TxBps: 2.5, RxBpsRaw: 3, TxBpsRaw: 4}, map[string]WindowCounters{
		"1m": {RxBytes: 10, TxBytes: 20},
	})
	require.Equal(t, int64(100), tr.Total.RxBytes)
	require.Equal(t, 1.5, tr.Rate.RxBps)
	require.Equal(t, int64(10), tr.Windows["1m"].RxBytes)
}

func TestComputeRateAndEWMA(t *testing.T) {
	t0 := time.Unix(0, 0).UTC()
	t1 := t0.Add(2 * time.Second)
	r := ComputeRate(Sample{Time: t0, Rx: 100, Tx: 50}, Sample{Time: t1, Rx: 300, Tx: 150})
	require.Equal(t, 100.0, r.RxBps) // 200 bytes / 2s
	require.Equal(t, 50.0, r.TxBps)
	require.InDelta(t, 70.0, EWMA(100, 0, 0.3), 0.001)
}
