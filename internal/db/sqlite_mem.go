package db

// Default SQLite memory budgets for edge-class nodes (~1–2 GiB RAM).
// The previous hard-coded 64+128 MiB page caches + 256+512 MiB mmap
// made wireguardd the OOM-killer target on small fleet nodes even with
// only a handful of peers.
const (
	DefaultStateCacheMiB      = 16
	DefaultStateMMapMiB       = 64
	DefaultTimeseriesCacheMiB = 16
	DefaultTimeseriesMMapMiB  = 64
)

// High-throughput budgets for large control-plane hosts (opt-in via config).
const (
	PerformanceStateCacheMiB      = 64
	PerformanceStateMMapMiB       = 256
	PerformanceTimeseriesCacheMiB = 128
	PerformanceTimeseriesMMapMiB  = 512
)

// SQLiteMem is the page-cache + mmap budget for one SQLite connection.
// CacheMiB maps to PRAGMA cache_size=-N (KiB). MMapMiB maps to PRAGMA mmap_size.
// Zero values resolve to the edge-safe defaults above.
type SQLiteMem struct {
	CacheMiB int
	MMapMiB  int
}

// Normalize fills zeros with defaults. timeseries selects the TS defaults.
func (m SQLiteMem) Normalize(timeseries bool) SQLiteMem {
	out := m
	if out.CacheMiB <= 0 {
		if timeseries {
			out.CacheMiB = DefaultTimeseriesCacheMiB
		} else {
			out.CacheMiB = DefaultStateCacheMiB
		}
	}
	if out.MMapMiB <= 0 {
		if timeseries {
			out.MMapMiB = DefaultTimeseriesMMapMiB
		} else {
			out.MMapMiB = DefaultStateMMapMiB
		}
	}
	return out
}

// PerformanceMem returns the old large-host budgets.
func PerformanceMem(timeseries bool) SQLiteMem {
	if timeseries {
		return SQLiteMem{CacheMiB: PerformanceTimeseriesCacheMiB, MMapMiB: PerformanceTimeseriesMMapMiB}
	}
	return SQLiteMem{CacheMiB: PerformanceStateCacheMiB, MMapMiB: PerformanceStateMMapMiB}
}

// BalancedMem is a mid-size profile (multi-GB nodes, moderate peer counts).
func BalancedMem(_ bool) SQLiteMem {
	return SQLiteMem{CacheMiB: 32, MMapMiB: 128}
}

// CompactMem is the edge-safe default profile.
func CompactMem(timeseries bool) SQLiteMem {
	if timeseries {
		return SQLiteMem{CacheMiB: DefaultTimeseriesCacheMiB, MMapMiB: DefaultTimeseriesMMapMiB}
	}
	return SQLiteMem{CacheMiB: DefaultStateCacheMiB, MMapMiB: DefaultStateMMapMiB}
}
