package db

import (
	"database/sql"
	"fmt"
	"strings"
)

// applyPerformancePragmas configures SQLite for high-volume workloads
// (traffic samples, frequent peer stat updates) while remaining durable under WAL.
//
// Profile summary:
//   - WAL journal + NORMAL sync (safe with WAL, much faster than FULL)
//   - large page cache + mmap for read-heavy window queries
//   - temp objects in memory
//   - busy_timeout so writers retry instead of failing
//   - incremental auto_vacuum when the DB is still empty (new installs)
func applyPerformancePragmas(sqlDB *sql.DB, memory bool) error {
	// Core performance + safety set. Order matters lightly: journal_mode first.
	stmts := []string{
		`PRAGMA foreign_keys=ON`,
		`PRAGMA busy_timeout=10000`,
		`PRAGMA temp_store=MEMORY`,
		`PRAGMA recursive_triggers=ON`,
		`PRAGMA secure_delete=OFF`,
		// Cache: negative cache_size is KiB → 64 MiB page cache.
		`PRAGMA cache_size=-65536`,
	}
	if !memory {
		stmts = append([]string{
			`PRAGMA journal_mode=WAL`,
			// NORMAL is the recommended WAL durability/speed trade-off.
			`PRAGMA synchronous=NORMAL`,
			// Memory-map the DB file for faster large sequential/range reads.
			`PRAGMA mmap_size=268435456`, // 256 MiB
			// Keep WAL from growing without bound under heavy sample inserts.
			`PRAGMA wal_autocheckpoint=1000`,
			`PRAGMA journal_size_limit=67108864`, // 64 MiB
		}, stmts...)
	} else {
		// In-memory: still want speed; journal mode is typically "memory".
		stmts = append([]string{
			`PRAGMA synchronous=OFF`,
		}, stmts...)
	}

	for _, q := range stmts {
		if _, err := sqlDB.Exec(q); err != nil {
			// Some builds reject individual pragmas; keep going for non-critical ones.
			if isCriticalPragma(q) {
				return fmt.Errorf("%s: %w", q, err)
			}
		}
	}
	return nil
}

// enableIncrementalVacuum sets auto_vacuum=INCREMENTAL on a brand-new empty DB.
// Must run before any tables are created. Safe no-op on existing databases.
func enableIncrementalVacuum(sqlDB *sql.DB) {
	var tables int
	_ = sqlDB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table'`).Scan(&tables)
	if tables > 0 {
		return
	}
	// Setting alone is not enough on some builds — VACUUM materializes the mode.
	_, _ = sqlDB.Exec(`PRAGMA auto_vacuum=INCREMENTAL`)
	_, _ = sqlDB.Exec(`VACUUM`)
	_, _ = sqlDB.Exec(`PRAGMA auto_vacuum=INCREMENTAL`)
}

func isCriticalPragma(q string) bool {
	u := strings.ToUpper(q)
	return strings.Contains(u, "FOREIGN_KEYS") ||
		strings.Contains(u, "JOURNAL_MODE") ||
		strings.Contains(u, "BUSY_TIMEOUT")
}

// pragmaGet returns a single PRAGMA value as string (for diagnostics/tests).
func pragmaGet(sqlDB *sql.DB, name string) (string, error) {
	row := sqlDB.QueryRow(`PRAGMA ` + name)
	var v any
	if err := row.Scan(&v); err != nil {
		return "", err
	}
	switch t := v.(type) {
	case string:
		return t, nil
	case []byte:
		return string(t), nil
	case int64:
		return fmt.Sprintf("%d", t), nil
	case int:
		return fmt.Sprintf("%d", t), nil
	case float64:
		return fmt.Sprintf("%g", t), nil
	default:
		return fmt.Sprint(t), nil
	}
}

// PerformanceInfo is a snapshot of active SQLite performance settings.
type PerformanceInfo struct {
	JournalMode    string `json:"journal_mode"`
	Synchronous    string `json:"synchronous"`
	CacheSize      string `json:"cache_size"`
	MMapSize       string `json:"mmap_size"`
	TempStore      string `json:"temp_store"`
	BusyTimeout    string `json:"busy_timeout"`
	AutoVacuum     string `json:"auto_vacuum"`
	WALAutoChkpt   string `json:"wal_autocheckpoint"`
	ForeignKeys    string `json:"foreign_keys"`
	PageSize       string `json:"page_size"`
	PageCount      string `json:"page_count"`
	FreelistCount  string `json:"freelist_count"`
	JournalSizeLim string `json:"journal_size_limit"`
}

// Optimize runs SQLite's query planner maintenance on the state DB.
func (s *Store) Optimize() {
	if s.db != nil {
		_, _ = s.db.Exec(`PRAGMA optimize`)
	}
	if s.ts != nil {
		_, _ = s.ts.Exec(`PRAGMA optimize`)
	}
}

// CheckpointWAL flushes the write-ahead log into the state DB file (TRUNCATE).
func (s *Store) CheckpointWAL() error {
	_, err := s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// IncrementalVacuum reclaims free pages on the state DB.
func (s *Store) IncrementalVacuum(pages int) {
	if pages < 0 {
		pages = 0
	}
	_, _ = s.db.Exec(fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, pages))
}
