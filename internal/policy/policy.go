package policy

import "github.com/reloadlife/wireguardd/internal/db"

// EffectiveBytes returns user-visible total traffic.
func EffectiveBytes(p db.Peer) int64 {
	return p.EffectiveRx() + p.EffectiveTx()
}

// TrafficLimitExceeded reports whether the peer is over quota.
func TrafficLimitExceeded(p db.Peer) bool {
	if p.TrafficLimitBytes <= 0 {
		return false
	}
	return EffectiveBytes(p) >= p.TrafficLimitBytes
}

// ShouldAutoSuspend returns true if policy demands suspension.
func ShouldAutoSuspend(p db.Peer) bool {
	if p.Suspended {
		return false // already suspended
	}
	return TrafficLimitExceeded(p)
}
