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
	db *sql.DB
}

// Open opens (or creates) the database and runs migrations.
func Open(path string) (*Store, error) {
	if path != ":memory:" && path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, fmt.Errorf("create db dir: %w", err)
		}
	}
	dsn := path
	if path != ":memory:" {
		dsn = "file:" + path + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)"
	} else {
		dsn = "file:memdb1?mode=memory&cache=shared&_pragma=foreign_keys(1)"
	}
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	if _, err := sqlDB.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		_ = sqlDB.Close()
		return nil, fmt.Errorf("pragma: %w", err)
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
	if path != ":memory:" && path != "" {
		_ = os.Chmod(path, 0o600)
	}
	return &Store{db: sqlDB}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// DB exposes the underlying *sql.DB (for tests).
func (s *Store) DB() *sql.DB { return s.db }

// Ping checks connectivity.
func (s *Store) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
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
