package metrics

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/stats"
)

func TestWALMetrics(t *testing.T) {
	dir := t.TempDir()
	wal := filepath.Join(dir, "state.db-wal")
	require.NoError(t, os.WriteFile(wal, make([]byte, 4096), 0o600))

	reg := prometheus.NewRegistry()
	c := New(stats.NewCache(), reg)
	c.WatchWAL(map[string]string{"state": wal, "timeseries": filepath.Join(dir, "missing-wal")})
	c.ObserveWALCheckpoint("state", false)
	c.ObserveWALCheckpoint("state", false)
	c.ObserveWALCheckpoint("timeseries", true)

	require.NoError(t, testutil.GatherAndCompare(reg, strings.NewReader(`
# HELP wireguardd_sqlite_wal_bytes Size of the SQLite -wal file on disk
# TYPE wireguardd_sqlite_wal_bytes gauge
wireguardd_sqlite_wal_bytes{db="state"} 4096
wireguardd_sqlite_wal_bytes{db="timeseries"} 0
# HELP wireguardd_sqlite_wal_checkpoint_blocked_total Periodic WAL checkpoints that could not copy every frame back (a reader pins the WAL)
# TYPE wireguardd_sqlite_wal_checkpoint_blocked_total counter
wireguardd_sqlite_wal_checkpoint_blocked_total{db="state"} 2
`), "wireguardd_sqlite_wal_bytes", "wireguardd_sqlite_wal_checkpoint_blocked_total"))
	require.Equal(t, 1, testutil.CollectAndCount(reg, "wireguardd_sqlite_wal_last_checkpoint_timestamp_seconds"))
}
