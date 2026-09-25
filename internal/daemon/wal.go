package daemon

import (
	"context"
	"time"

	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/metrics"
)

// walCheckpointInterval bounds WAL growth between checkpoints. SQLite's own
// auto-checkpoint is PASSIVE, never truncates, and fails silently; this loop
// makes a pinned WAL visible in logs and metrics within minutes instead of
// when the disk fills (sky-ams-1, 2026-09-10 and 2026-09-21).
const walCheckpointInterval = 5 * time.Minute

func (a *App) maintainWAL(ctx context.Context, store *db.Store, m *metrics.Collector) {
	t := time.NewTicker(walCheckpointInterval)
	defer t.Stop()
	for {
		for _, st := range store.CheckpointWALs(ctx) {
			if ctx.Err() != nil {
				return
			}
			m.ObserveWALCheckpoint(st.DB, st.Err == nil)
			if st.Err != nil {
				a.log.Warn("sqlite wal checkpoint incomplete",
					"db", st.DB,
					"wal_bytes", st.WALBytes,
					"busy", st.Checkpoint.Busy,
					"log_frames", st.Checkpoint.LogFrames,
					"checkpointed_frames", st.Checkpoint.CheckpointedFrames,
					"err", st.Err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
