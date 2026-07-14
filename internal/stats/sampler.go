package stats

import "time"

// Sample is a traffic observation.
type Sample struct {
	Time time.Time
	Rx   int64
	Tx   int64
}

// RateResult is computed rate between two samples.
type RateResult struct {
	RxBps float64
	TxBps float64
}

// ComputeRate calculates bytes/sec between prev and cur.
// Counter resets (negative delta) yield 0 for that direction.
func ComputeRate(prev, cur Sample) RateResult {
	if cur.Time.Before(prev.Time) || cur.Time.Equal(prev.Time) {
		return RateResult{}
	}
	dt := cur.Time.Sub(prev.Time).Seconds()
	if dt <= 0 {
		return RateResult{}
	}
	var rx, tx float64
	if cur.Rx >= prev.Rx {
		rx = float64(cur.Rx-prev.Rx) / dt
	}
	if cur.Tx >= prev.Tx {
		tx = float64(cur.Tx-prev.Tx) / dt
	}
	return RateResult{RxBps: rx, TxBps: tx}
}

// EWMA smooths a rate series.
func EWMA(prev, sample, alpha float64) float64 {
	if alpha <= 0 {
		alpha = 0.3
	}
	if alpha > 1 {
		alpha = 1
	}
	return alpha*sample + (1-alpha)*prev
}
