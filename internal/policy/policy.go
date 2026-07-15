package policy

import (
	"strings"
	"time"

	"github.com/reloadlife/wireguardd/internal/db"
)

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

// ParseExpiresAt parses peer.ExpiresAt (RFC3339 or RFC3339Nano). Empty → zero time, nil error.
func ParseExpiresAt(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, nil
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	return time.Parse(time.RFC3339, s)
}

// IsExpired reports whether expires_at is set and now is at or past it.
func IsExpired(p db.Peer, now time.Time) bool {
	if p.ExpiresAt == "" {
		return false
	}
	t, err := ParseExpiresAt(p.ExpiresAt)
	if err != nil || t.IsZero() {
		return false
	}
	return !now.Before(t)
}

// ShouldAutoSuspend returns true if policy demands suspension.
func ShouldAutoSuspend(p db.Peer) bool {
	return ShouldAutoSuspendAt(p, time.Now().UTC())
}

// ShouldAutoSuspendAt is ShouldAutoSuspend with an explicit clock (tests).
func ShouldAutoSuspendAt(p db.Peer, now time.Time) bool {
	if p.Suspended {
		return false // already suspended
	}
	if IsExpired(p, now) {
		return true
	}
	return TrafficLimitExceeded(p)
}

// AutoSuspendReason returns a short reason when ShouldAutoSuspend would fire.
// Empty if no auto-suspend is required. Prefer expire over traffic when both apply.
func AutoSuspendReason(p db.Peer, now time.Time) string {
	if p.Suspended {
		return ""
	}
	if IsExpired(p, now) {
		return "expired"
	}
	if TrafficLimitExceeded(p) {
		return "traffic_limit"
	}
	return ""
}

// EffectiveBandwidth expands a combined total cap into per-direction limits.
// If total > 0 and a direction is 0, that direction inherits total.
// Explicit non-zero rx/tx keep their values (per-direction override).
func EffectiveBandwidth(rx, tx, total int64) (rxOut, txOut int64) {
	rxOut, txOut = rx, tx
	if total <= 0 {
		return rxOut, txOut
	}
	if rxOut <= 0 {
		rxOut = total
	}
	if txOut <= 0 {
		txOut = total
	}
	return rxOut, txOut
}
