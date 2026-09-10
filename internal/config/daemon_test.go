package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMemoryProfileDefaults(t *testing.T) {
	cfg, err := LoadDaemon("")
	require.NoError(t, err)
	require.Equal(t, "compact", cfg.DB.MemoryProfile)

	c, m := cfg.StateSQLiteMem()
	require.Equal(t, 16, c)
	require.Equal(t, 64, m)
	c, m = cfg.TimeseriesSQLiteMem()
	require.Equal(t, 16, c)
	require.Equal(t, 64, m)
}

func TestMemoryProfilePerformanceAndOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
db:
  path: /tmp/x.db
  memory_profile: performance
  timeseries_cache_mb: 24
auth:
  token: test
`), 0o600))

	cfg, err := LoadDaemon(path)
	require.NoError(t, err)
	require.Equal(t, "performance", cfg.DB.MemoryProfile)

	c, m := cfg.StateSQLiteMem()
	require.Equal(t, 64, c)
	require.Equal(t, 256, m)
	c, m = cfg.TimeseriesSQLiteMem()
	require.Equal(t, 24, c) // override
	require.Equal(t, 512, m)
}

func TestSampleRetention(t *testing.T) {
	cfg, err := LoadDaemon("")
	require.NoError(t, err)
	require.Equal(t, 7*24*time.Hour, cfg.SampleRetention())

	dir := t.TempDir()
	path := filepath.Join(dir, "cfg.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
wireguard:
  sample_retention: 6h
auth:
  token: test
`), 0o600))
	cfg, err = LoadDaemon(path)
	require.NoError(t, err)
	require.Equal(t, 6*time.Hour, cfg.SampleRetention())
}
