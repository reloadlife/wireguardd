package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/reloadlife/wireguardd/migrations"
)

// Store wraps the state SQLite DB plus a dedicated timeseries SQLite DB.
//
//	state.db       — interfaces, peers, events (source of truth)
//	timeseries.db  — traffic_samples only (high-volume writes)
type Store struct {
	db     *sql.DB // state
	ts     *sql.DB // timeseries
	memory bool
	tsPath string
}

// OpenOptions configures both SQLite files.
type OpenOptions struct {
	// Path is the state database path (desired config SoT).
	Path string
	// TimeseriesPath is the samples database. Empty → DefaultTimeseriesPath(Path).
	TimeseriesPath string
}

// Open opens state + timeseries databases (timeseries path auto-derived).
func Open(path string) (*Store, error) {
	return OpenWithOptions(OpenOptions{Path: path})
}

// OpenWithOptions opens state and timeseries SQLite files with performance profiles.
func OpenWithOptions(opts OpenOptions) (*Store, error) {
	tsPath := opts.TimeseriesPath
	if tsPath == "" {
		tsPath = DefaultTimeseriesPath(opts.Path)
	}

	// 1) Open timeseries first and ensure schema (needed for legacy sample migrate).
	tsDB, tsMem, err := openSQLite(tsPath, true)
	if err != nil {
		return nil, fmt.Errorf("open timeseries db: %w", err)
	}
	if err := ensureTimeseriesSchema(tsDB); err != nil {
		_ = tsDB.Close()
		return nil, err
	}

	// 2) Open state DB.
	stateDB, stateMem, err := openSQLite(opts.Path, false)
	if err != nil {
		_ = tsDB.Close()
		return nil, fmt.Errorf("open state db: %w", err)
	}

	// 3) Copy legacy samples out of state before migration 00005 drops them.
	if _, err := migrateLegacySamples(stateDB, tsDB, tsPath); err != nil {
		_ = stateDB.Close()
		_ = tsDB.Close()
		return nil, fmt.Errorf("migrate legacy samples: %w", err)
	}

	// 4) State schema migrations (00005 drops traffic_samples from state).
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = stateDB.Close()
		_ = tsDB.Close()
		return nil, err
	}
	if err := goose.Up(stateDB, "."); err != nil {
		_ = stateDB.Close()
		_ = tsDB.Close()
		return nil, fmt.Errorf("migrate state: %w", err)
	}

	// Re-apply pragmas after goose.
	if err := applyPerformancePragmas(stateDB, stateMem); err != nil {
		_ = stateDB.Close()
		_ = tsDB.Close()
		return nil, fmt.Errorf("state pragmas: %w", err)
	}
	if err := applyPerformancePragmas(tsDB, tsMem); err != nil {
		_ = stateDB.Close()
		_ = tsDB.Close()
		return nil, fmt.Errorf("timeseries pragmas: %w", err)
	}
	if !tsMem {
		_, _ = tsDB.Exec(`PRAGMA cache_size=-131072`)
		_, _ = tsDB.Exec(`PRAGMA mmap_size=536870912`)
		_, _ = tsDB.Exec(`PRAGMA foreign_keys=OFF`)
	}
	_, _ = stateDB.Exec(`PRAGMA optimize`)
	_, _ = tsDB.Exec(`PRAGMA optimize`)

	return &Store{
		db:     stateDB,
		ts:     tsDB,
		memory: stateMem && tsMem,
		tsPath: tsPath,
	}, nil
}

// Close optimizes and closes both databases.
func (s *Store) Close() error {
	var first error
	if s.ts != nil {
		_, _ = s.ts.Exec(`PRAGMA optimize`)
		if !s.memory {
			_, _ = s.ts.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
		}
		if err := s.ts.Close(); err != nil && first == nil {
			first = err
		}
		s.ts = nil
	}
	if s.db != nil {
		s.Optimize()
		if !s.memory {
			_ = s.CheckpointWAL()
		}
		if err := s.db.Close(); err != nil && first == nil {
			first = err
		}
		s.db = nil
	}
	return first
}

// DB exposes the underlying state *sql.DB (for tests).
func (s *Store) DB() *sql.DB { return s.db }

// TSDB exposes the timeseries *sql.DB (for tests).
func (s *Store) TSDB() *sql.DB { return s.ts }

// TimeseriesPath returns the path/URI of the timeseries database.
func (s *Store) TimeseriesPath() string { return s.tsPath }

// Ping checks both databases.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.db.PingContext(ctx); err != nil {
		return err
	}
	if s.ts != nil {
		return s.ts.PingContext(ctx)
	}
	return nil
}

// WithTx runs fn inside a single state-DB transaction.
func (s *Store) WithTx(ctx context.Context, fn func(tx *sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit tx: %w", err)
	}
	return nil
}

// PerformanceInfoPair reports pragmas for state + timeseries files.
type PerformanceInfoPair struct {
	State      PerformanceInfo `json:"state"`
	Timeseries PerformanceInfo `json:"timeseries"`
	TSPath     string          `json:"timeseries_path"`
}

// PerformanceInfoBoth reads PRAGMA profiles for both DBs.
func (s *Store) PerformanceInfoBoth() (PerformanceInfoPair, error) {
	st, err := s.performanceInfoDB(s.db)
	if err != nil {
		return PerformanceInfoPair{}, err
	}
	var ts PerformanceInfo
	if s.ts != nil {
		ts, err = s.performanceInfoDB(s.ts)
		if err != nil {
			return PerformanceInfoPair{}, err
		}
	}
	return PerformanceInfoPair{State: st, Timeseries: ts, TSPath: s.tsPath}, nil
}

func (s *Store) performanceInfoDB(sqlDB *sql.DB) (PerformanceInfo, error) {
	get := func(name string) string {
		v, _ := pragmaGet(sqlDB, name)
		return v
	}
	return PerformanceInfo{
		JournalMode:    get("journal_mode"),
		Synchronous:    get("synchronous"),
		CacheSize:      get("cache_size"),
		MMapSize:       get("mmap_size"),
		TempStore:      get("temp_store"),
		BusyTimeout:    get("busy_timeout"),
		AutoVacuum:     get("auto_vacuum"),
		WALAutoChkpt:   get("wal_autocheckpoint"),
		ForeignKeys:    get("foreign_keys"),
		PageSize:       get("page_size"),
		PageCount:      get("page_count"),
		FreelistCount:  get("freelist_count"),
		JournalSizeLim: get("journal_size_limit"),
	}, nil
}

// PerformanceInfo reads the state DB profile (compat).
func (s *Store) PerformanceInfo() (PerformanceInfo, error) {
	return s.performanceInfoDB(s.db)
}

func nowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t, err = time.Parse(time.RFC3339, s)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}
