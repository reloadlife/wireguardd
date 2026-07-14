package db

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pressly/goose/v3"
	_ "modernc.org/sqlite"

	"github.com/reloadlife/wireguardd/migrations"
)

// Store wraps the SQLite connection.
type Store struct {
	db     *sql.DB
	memory bool
}

// Open opens (or creates) the database, enables the performance profile, and runs migrations.
func Open(path string) (*Store, error) {
	memory := path == ":memory:" || path == ""
	if !memory {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}

	// DSN: enable busy_timeout + foreign_keys at connection init (modernc applies _pragma per conn).
	// Full performance profile is applied again via Exec so values are verified and complete.
	var dsn string
	if memory {
		dsn = "file:memdb1?mode=memory&cache=shared" +
			"&_pragma=foreign_keys(1)" +
			"&_pragma=busy_timeout(10000)" +
			"&_pragma=temp_store(MEMORY)" +
			"&_pragma=synchronous(OFF)"
	} else {
		dsn = "file:" + path +
			"?_pragma=busy_timeout(10000)" +
			"&_pragma=foreign_keys(1)" +
			"&_pragma=journal_mode(WAL)" +
			"&_pragma=synchronous(NORMAL)" +
			"&_pragma=temp_store(MEMORY)" +
			"&_pragma=cache_size(-65536)" +
			"&_pragma=mmap_size(268435456)"
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	// Single writer connection — SQLite + modernc is safest this way; WAL still allows
	// concurrent readers via the same connection pool serialization.
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	sqlDB.SetConnMaxIdleTime(0)

	// Incremental vacuum only sticks on an empty DB — do this before migrations.
	if !memory {
		enableIncrementalVacuum(sqlDB)
	}

	if err := applyPerformancePragmas(sqlDB, memory); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("sqlite performance pragmas: %w", err)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		_ = sqlDB.Close()
		return nil, err
	}
	if err := goose.Up(sqlDB, "."); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	// Re-apply post-migration (goose may open nested connections; keep profile sticky).
	if err := applyPerformancePragmas(sqlDB, memory); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("sqlite performance pragmas (post-migrate): %w", err)
	}

	if !memory && path != "" {
		_ = os.Chmod(path, 0o600)
	}

	// Nudge the query planner after schema is in place.
	_, _ = sqlDB.Exec(`PRAGMA optimize`)

	return &Store{db: sqlDB, memory: memory}, nil
}

// Close optimizes then closes the database.
func (s *Store) Close() error {
	if s.db == nil {
		return nil
	}
	s.Optimize()
	if !s.memory {
		// Best-effort WAL flush so the main file is consistent on disk.
		_ = s.CheckpointWAL()
	}
	return s.db.Close()
}

// DB exposes the underlying *sql.DB (for tests).
func (s *Store) DB() *sql.DB { return s.db }

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

// WithTx runs fn inside a single SQLite transaction (batched writes for high volume).
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
