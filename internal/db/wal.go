package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ErrWALCheckpointBlocked means SQLite could not copy every WAL frame back into
// the database file because a read transaction still pins an older snapshot.
// Until that reader ends the WAL can only grow.
var ErrWALCheckpointBlocked = errors.New("sqlite wal checkpoint blocked by an open read transaction")

// WALCheckpoint is the row PRAGMA wal_checkpoint returns.
type WALCheckpoint struct {
	Busy               bool
	LogFrames          int64
	CheckpointedFrames int64
}

// Complete reports whether every frame in the WAL reached the database file.
// A non-WAL database reports -1 for both counts, which is also complete.
func (c WALCheckpoint) Complete() bool {
	return !c.Busy && c.CheckpointedFrames == c.LogFrames
}

// WALStat is one database's WAL after a checkpoint attempt.
type WALStat struct {
	DB         string // "state" or "timeseries"
	WALBytes   int64  // size of the -wal file afterwards; 0 when absent
	Checkpoint WALCheckpoint
	Err        error
}

// CheckpointWAL checkpoints the state DB and truncates its WAL. It returns
// ErrWALCheckpointBlocked when a reader pins the WAL — a result that
// Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) silently discards.
func (s *Store) CheckpointWAL() error {
	_, err := checkpointWAL(context.Background(), s.db)
	return err
}

// CheckpointWALs checkpoints both file-backed databases and reports each WAL.
// In-memory databases have no WAL and are skipped.
func (s *Store) CheckpointWALs(ctx context.Context) []WALStat {
	var out []WALStat
	for _, d := range []struct {
		name string
		db   *sql.DB
		path string
	}{
		{"state", s.db, s.statePath},
		{"timeseries", s.ts, s.tsPath},
	} {
		wal := walPath(d.path)
		if d.db == nil || wal == "" {
			continue
		}
		c, err := checkpointWAL(ctx, d.db)
		out = append(out, WALStat{DB: d.name, WALBytes: fileSize(wal), Checkpoint: c, Err: err})
	}
	return out
}

// WALFiles maps "state"/"timeseries" to the -wal path of each file-backed DB.
func (s *Store) WALFiles() map[string]string {
	out := map[string]string{}
	if p := walPath(s.statePath); p != "" {
		out["state"] = p
	}
	if p := walPath(s.tsPath); p != "" {
		out["timeseries"] = p
	}
	return out
}

// checkpointWAL runs PASSIVE first so a pinned reader is reported at once
// instead of stalling the single pooled connection for busy_timeout. Only a
// complete PASSIVE is followed by TRUNCATE, which resets the -wal file to 0.
func checkpointWAL(ctx context.Context, sqlDB *sql.DB) (WALCheckpoint, error) {
	c, err := walCheckpoint(ctx, sqlDB, "PASSIVE")
	if err != nil || !c.Complete() {
		return c, err
	}
	return walCheckpoint(ctx, sqlDB, "TRUNCATE")
}

func walCheckpoint(ctx context.Context, sqlDB *sql.DB, mode string) (WALCheckpoint, error) {
	var c WALCheckpoint
	var busy int
	if err := sqlDB.QueryRowContext(ctx, `PRAGMA wal_checkpoint(`+mode+`)`).
		Scan(&busy, &c.LogFrames, &c.CheckpointedFrames); err != nil {
		return c, fmt.Errorf("wal_checkpoint(%s): %w", mode, err)
	}
	c.Busy = busy != 0
	if !c.Complete() {
		return c, fmt.Errorf("%w: wal_checkpoint(%s) busy=%d log=%d checkpointed=%d",
			ErrWALCheckpointBlocked, mode, busy, c.LogFrames, c.CheckpointedFrames)
	}
	return c, nil
}

// walPath returns the -wal sibling of a file-backed DB path, or "" for memory.
func walPath(path string) string {
	if path == "" || path == ":memory:" {
		return ""
	}
	if strings.HasPrefix(path, "file:") {
		if strings.Contains(path, "mode=memory") {
			return ""
		}
		path = strings.TrimPrefix(path, "file:")
		if i := strings.IndexByte(path, '?'); i >= 0 {
			path = path[:i]
		}
	}
	return path + "-wal"
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}
