package db_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/db"
)

func openFileStore(t *testing.T) (*db.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := db.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store, path
}

// passiveCheckpoint runs PRAGMA wal_checkpoint(PASSIVE) from a separate
// connection, the way an operator would from the sqlite3 shell.
func passiveCheckpoint(t *testing.T, probe *sql.DB) (busy, logFrames, checkpointed int) {
	t.Helper()
	require.NoError(t, probe.QueryRow(`PRAGMA wal_checkpoint(PASSIVE)`).Scan(&busy, &logFrames, &checkpointed))
	return busy, logFrames, checkpointed
}

// modernc.org/sqlite before v1.41.0 dropped the *rows of a query whose context
// was cancelled just after its first step, leaving the statement un-finalized
// on the store's only pooled connection. That connection then sat in a read
// transaction forever: writes kept succeeding, auto-checkpoint could never
// get past the pinned snapshot, and state.db-wal grew until the disk filled
// (wireguardd on het 2026-09-03 and sky-ams-1 2026-09-10; openvpnd on het and sky).
//
// API handlers and the reconcile loop both run queries on contexts that get
// cancelled (client disconnects, shutdown), so this races cancellation
// against reads interleaved with writes and asserts the WAL stays drainable.
func TestCancelledQueriesDoNotPinWAL(t *testing.T) {
	store, path := openFileStore(t)
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		require.NoError(t, store.AddEvent(ctx, "info", "seed", "", "", fmt.Sprint(i), "{}"))
	}

	probe, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = probe.Close() })

	const (
		iterations = 40000
		budget     = 8 * time.Second
		checkEvery = 500
	)
	deadline := time.Now().Add(budget)
	cancelled := 0
	for i := 0; i < iterations && time.Now().Before(deadline); i++ {
		qctx, cancel := context.WithCancel(ctx)
		// Spread the cancel across the query's lifetime so some land between
		// sqlite3_step returning a row and the driver handing the rows back.
		spin := (i * 7919) % 4000
		go func() {
			x := 0
			for j := 0; j < spin; j++ {
				x += j
			}
			_ = x
			cancel()
		}()
		runtime.Gosched()
		if _, err := store.ListEvents(qctx, 5); errors.Is(err, context.Canceled) {
			cancelled++
		}
		cancel()
		require.NoError(t, store.AddEvent(ctx, "info", "tick", "", "", "w", "{}"))

		if i%checkEvery == checkEvery-1 {
			busy, logFrames, ckpt := passiveCheckpoint(t, probe)
			require.Truef(t, busy == 0 && logFrames == ckpt,
				"iteration %d: WAL pinned by a leaked reader (busy=%d log=%d checkpointed=%d, %d cancelled queries)",
				i, busy, logFrames, ckpt, cancelled)
		}
	}
	require.Positive(t, cancelled, "no query was cancelled mid-flight; the race was not exercised")
	require.NoError(t, store.CheckpointWAL())
	t.Logf("%d cancelled queries, WAL still drains", cancelled)
}

// A pinned WAL used to be invisible: CheckpointWAL ran the pragma through
// Exec and discarded the busy/log/checkpointed row.
func TestCheckpointWALReportsPinnedReader(t *testing.T) {
	store, path := openFileStore(t)
	ctx := context.Background()
	require.NoError(t, store.AddEvent(ctx, "info", "seed", "", "", "", "{}"))

	reader, err := sql.Open("sqlite", "file:"+path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })
	tx, err := reader.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	require.NoError(t, err)
	var n int
	require.NoError(t, tx.QueryRow(`SELECT COUNT(*) FROM events`).Scan(&n))

	for i := 0; i < 50; i++ {
		require.NoError(t, store.AddEvent(ctx, "info", "tick", "", "", "", "{}"))
	}

	start := time.Now()
	err = store.CheckpointWAL()
	require.ErrorIs(t, err, db.ErrWALCheckpointBlocked)
	require.Less(t, time.Since(start), 2*time.Second, "a pinned WAL must be reported, not waited out for busy_timeout")

	stats := store.CheckpointWALs(ctx)
	require.Len(t, stats, 2)
	require.Equal(t, "state", stats[0].DB)
	require.ErrorIs(t, stats[0].Err, db.ErrWALCheckpointBlocked)
	require.Positive(t, stats[0].WALBytes)
	require.Greater(t, stats[0].Checkpoint.LogFrames, stats[0].Checkpoint.CheckpointedFrames)
	require.Equal(t, "timeseries", stats[1].DB)
	require.NoError(t, stats[1].Err)

	require.NoError(t, tx.Rollback())
	require.NoError(t, store.CheckpointWAL())
	stats = store.CheckpointWALs(ctx)
	require.NoError(t, stats[0].Err)
	require.Zero(t, stats[0].WALBytes, "TRUNCATE should reset the -wal file")

	files := store.WALFiles()
	require.Equal(t, path+"-wal", files["state"])
	require.Equal(t, filepath.Join(filepath.Dir(path), "timeseries.db-wal"), files["timeseries"])
}

func TestWALFilesSkipsMemory(t *testing.T) {
	store, err := db.Open(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	require.Empty(t, store.WALFiles())
	require.Empty(t, store.CheckpointWALs(context.Background()))
}
