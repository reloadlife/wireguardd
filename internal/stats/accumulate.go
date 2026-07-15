package stats

// AccumulateLifetime advances a durable lifetime total using a volatile data-plane
// counter (WireGuard kernel transfer counters, etc.).
//
// Kernel counters reset when an interface is recreated or the host reboots.
// lifetime must not drop when that happens.
//
// prevRaw is the previous observation of the data-plane counter; hasPrev is false
// when this process has not yet sampled this series (e.g. first tick after start).
func AccumulateLifetime(lifetime, raw, prevRaw int64, hasPrev bool) int64 {
	if hasPrev {
		if raw >= prevRaw {
			return lifetime + (raw - prevRaw)
		}
		// Mid-process counter reset: all of raw is new traffic in this session.
		return lifetime + raw
	}
	// First observation after process start (or first ever).
	if raw >= lifetime {
		// Cold start, or counters continued while we were down.
		return raw
	}
	// Reboot/restart: data-plane is behind durable lifetime — keep lifetime.
	// Caller should seed prevRaw=raw so subsequent deltas accumulate correctly.
	return lifetime
}
