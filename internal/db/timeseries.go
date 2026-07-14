package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultTimeseriesPath returns the default timeseries DB path beside the state DB.
//
//	state.db        → timeseries.db (same directory)
//	:memory: / ""   → in-memory shared cache DB
func DefaultTimeseriesPath(statePath string) string {
	if statePath == "" || statePath == ":memory:" {
		return "file:wireguardd_ts?mode=memory&cache=shared"
	}
	dir := filepath.Dir(statePath)
	return filepath.Join(dir, "timeseries.db")
}

// openSQLite opens a SQLite DB with the performance profile.
// timeseries=true uses a write-heavy tuned profile (no FK, larger cache).
func openSQLite(path string, timeseries bool) (*sql.DB, bool, error) {
	memory := path == "" || path == ":memory:" || strings.HasPrefix(path, "file:") && strings.Contains(path, "mode=memory")
	if !memory && !strings.HasPrefix(path, "file:") {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, false, fmt.Errorf("create db dir: %w", err)
		}
	}

	var dsn string
	switch {
	case memory && strings.HasPrefix(path, "file:"):
		dsn = path
		if !strings.Contains(dsn, "_pragma") {
			dsn += "&_pragma=busy_timeout(10000)&_pragma=temp_store(MEMORY)&_pragma=synchronous(OFF)"
		}
	case memory:
		name := "mem_state"
		if timeseries {
			name = "mem_ts"
		}
		dsn = fmt.Sprintf("file:%s?mode=memory&cache=shared&_pragma=busy_timeout(10000)&_pragma=temp_store(MEMORY)&_pragma=synchronous(OFF)", name)
	default:
		// Timeseries: no foreign_keys (peer rows live in state.db), bigger cache for hot inserts.
		if timeseries {
			dsn = "file:" + path +
				"?_pragma=busy_timeout(10000)" +
				"&_pragma=journal_mode(WAL)" +
				"&_pragma=synchronous(NORMAL)" +
				"&_pragma=temp_store(MEMORY)" +
				"&_pragma=cache_size(-131072)" + // 128 MiB
				"&_pragma=mmap_size(536870912)" // 512 MiB
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
	}

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, false, fmt.Errorf("open sqlite: %w", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)
	sqlDB.SetConnMaxLifetime(0)
	sqlDB.SetConnMaxIdleTime(0)

	if !memory {
		enableIncrementalVacuum(sqlDB)
	}
	if err := applyPerformancePragmas(sqlDB, memory); err != nil {
		_ = sqlDB.Close()
		return nil, false, err
	}
	// Timeseries: prefer a larger cache after shared pragma set.
	if timeseries && !memory {
		_, _ = sqlDB.Exec(`PRAGMA cache_size=-131072`)
		_, _ = sqlDB.Exec(`PRAGMA mmap_size=536870912`)
		_, _ = sqlDB.Exec(`PRAGMA foreign_keys=OFF`)
	}
	if !memory && path != "" && !strings.HasPrefix(path, "file:") {
		_ = os.Chmod(path, 0o600)
	}
	return sqlDB, memory, nil
}

// ensureTimeseriesSchema creates the samples table + indexes on the TS database.
// No FK to peers — state and timeseries are separate files.
func ensureTimeseriesSchema(ts *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS traffic_samples (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			peer_id INTEGER NOT NULL,
			sampled_at TEXT NOT NULL,
			rx_bytes INTEGER NOT NULL DEFAULT 0,
			tx_bytes INTEGER NOT NULL DEFAULT 0,
			rx_bps REAL NOT NULL DEFAULT 0,
			tx_bps REAL NOT NULL DEFAULT 0
		)`,
		`CREATE INDEX IF NOT EXISTS idx_ts_peer_time ON traffic_samples(peer_id, sampled_at DESC)`,
		`CREATE INDEX IF NOT EXISTS idx_ts_peer_time_asc ON traffic_samples(peer_id, sampled_at)`,
		`CREATE INDEX IF NOT EXISTS idx_ts_time ON traffic_samples(sampled_at)`,
	}
	for _, q := range stmts {
		if _, err := ts.Exec(q); err != nil {
			return fmt.Errorf("timeseries schema: %w", err)
		}
	}
	_, _ = ts.Exec(`PRAGMA optimize`)
	return nil
}

// migrateLegacySamples copies traffic_samples from the state DB into the timeseries DB
// (upgrades from pre-split installs). Safe if the table is missing or empty.
func migrateLegacySamples(state *sql.DB, ts *sql.DB, tsPath string) (int64, error) {
	var name string
	err := state.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='traffic_samples'`).Scan(&name)
	if err == sql.ErrNoRows || name == "" {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var n int64
	if err := state.QueryRow(`SELECT COUNT(*) FROM traffic_samples`).Scan(&n); err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, nil
	}

	// ATTACH timeseries file onto the state connection for a bulk cross-db copy.
	attachPath := tsPath
	if strings.HasPrefix(tsPath, "file:") {
		// In-memory attach uses the full URI.
		attachPath = tsPath
	}
	if _, err := state.Exec(`ATTACH DATABASE ? AS tsdb`, attachPath); err != nil {
		// Fallback: row-by-row via Go if ATTACH fails.
		return copySamplesRowByRow(state, ts)
	}
	defer func() { _, _ = state.Exec(`DETACH DATABASE tsdb`) }()

	// Ensure target table exists under the attached name (schema already on ts connection;
	// ATTACH sees the same file — table should exist). Create if missing.
	_, _ = state.Exec(`CREATE TABLE IF NOT EXISTS tsdb.traffic_samples (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		peer_id INTEGER NOT NULL,
		sampled_at TEXT NOT NULL,
		rx_bytes INTEGER NOT NULL DEFAULT 0,
		tx_bytes INTEGER NOT NULL DEFAULT 0,
		rx_bps REAL NOT NULL DEFAULT 0,
		tx_bps REAL NOT NULL DEFAULT 0
	)`)

	res, err := state.Exec(`
INSERT INTO tsdb.traffic_samples (peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps)
SELECT peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps FROM main.traffic_samples`)
	if err != nil {
		// main. prefix may fail; try unqualified
		res, err = state.Exec(`
INSERT INTO tsdb.traffic_samples (peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps)
SELECT peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps FROM traffic_samples`)
		if err != nil {
			_, _ = state.Exec(`DETACH DATABASE tsdb`)
			return copySamplesRowByRow(state, ts)
		}
	}
	moved, _ := res.RowsAffected()
	return moved, nil
}

func copySamplesRowByRow(state, ts *sql.DB) (int64, error) {
	rows, err := state.Query(`SELECT peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps FROM traffic_samples`)
	if err != nil {
		return 0, err
	}
	defer func() { _ = rows.Close() }()

	tx, err := ts.Begin()
	if err != nil {
		return 0, err
	}
	stmt, err := tx.Prepare(`INSERT INTO traffic_samples (peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	defer func() { _ = stmt.Close() }()

	var moved int64
	for rows.Next() {
		var peerID int64
		var sampledAt string
		var rx, txb int64
		var rxBps, txBps float64
		if err := rows.Scan(&peerID, &sampledAt, &rx, &txb, &rxBps, &txBps); err != nil {
			_ = tx.Rollback()
			return moved, err
		}
		if _, err := stmt.Exec(peerID, sampledAt, rx, txb, rxBps, txBps); err != nil {
			_ = tx.Rollback()
			return moved, err
		}
		moved++
	}
	if err := rows.Err(); err != nil {
		_ = tx.Rollback()
		return moved, err
	}
	if err := tx.Commit(); err != nil {
		return moved, err
	}
	return moved, nil
}
