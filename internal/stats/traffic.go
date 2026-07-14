package stats

import "time"

// Standard lookback windows for period counters.
var DefaultWindows = []WindowSpec{
	{Name: "1m", Duration: time.Minute},
	{Name: "5m", Duration: 5 * time.Minute},
	{Name: "15m", Duration: 15 * time.Minute},
	{Name: "1h", Duration: time.Hour},
	{Name: "24h", Duration: 24 * time.Hour},
}

// WindowSpec names a fixed lookback period.
type WindowSpec struct {
	Name     string
	Duration time.Duration
}

// ByteCounters are accumulative totals (bytes since soft-reset).
type ByteCounters struct {
	RxBytes int64 `json:"rx_bytes"`
	TxBytes int64 `json:"tx_bytes"`
}

// Rates are time-based throughput (bytes/sec).
type Rates struct {
	RxBps       float64 `json:"rx_bps"`                 // EWMA-smoothed
	TxBps       float64 `json:"tx_bps"`                 // EWMA-smoothed
	RxBpsRaw    float64 `json:"rx_bps_raw"`             // last sample interval
	TxBpsRaw    float64 `json:"tx_bps_raw"`             // last sample interval
	IntervalSec float64 `json:"interval_sec,omitempty"` // last sample dt
}

// WindowCounters are bytes transferred over a lookback window + average rate.
type WindowCounters struct {
	RxBytes  int64   `json:"rx_bytes"`
	TxBytes  int64   `json:"tx_bytes"`
	RxBpsAvg float64 `json:"rx_bps_avg"`
	TxBpsAvg float64 `json:"tx_bps_avg"`
	// SpanSec is actual sample span used (may be < nominal when history is short).
	SpanSec float64 `json:"span_sec,omitempty"`
}

// Traffic is the dual peer counter model: accumulative totals + time-based rates/windows.
type Traffic struct {
	Total   ByteCounters              `json:"total"`
	Rate    Rates                     `json:"rate"`
	Windows map[string]WindowCounters `json:"windows,omitempty"`
}

// WindowDelta computes bytes moved between a historical baseline and current totals.
// Soft-reset / counter wrap: if current < baseline, treat baseline as 0 (all current is in-window).
func WindowDelta(curRx, curTx, baseRx, baseTx int64, span time.Duration) WindowCounters {
	rx := curRx - baseRx
	tx := curTx - baseTx
	if rx < 0 {
		rx = curRx
	}
	if tx < 0 {
		tx = curTx
	}
	w := WindowCounters{RxBytes: rx, TxBytes: tx}
	sec := span.Seconds()
	if sec > 0 {
		w.SpanSec = sec
		w.RxBpsAvg = float64(rx) / sec
		w.TxBpsAvg = float64(tx) / sec
	}
	return w
}

// BuildTraffic assembles the dual counter view.
func BuildTraffic(totalRx, totalTx int64, rate Rates, windows map[string]WindowCounters) Traffic {
	t := Traffic{
		Total: ByteCounters{RxBytes: totalRx, TxBytes: totalTx},
		Rate:  rate,
	}
	if len(windows) > 0 {
		t.Windows = windows
	}
	return t
}
