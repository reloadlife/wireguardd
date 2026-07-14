-- +goose Up
-- Traffic samples live in a separate timeseries.db (high-volume writes).
-- Legacy rows are copied by Open() before this migration runs.
DROP INDEX IF EXISTS idx_samples_peer_time_asc;
DROP INDEX IF EXISTS idx_samples_time;
DROP INDEX IF EXISTS idx_samples_peer_time;
DROP TABLE IF EXISTS traffic_samples;

-- +goose Down
CREATE TABLE IF NOT EXISTS traffic_samples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE,
    sampled_at TEXT NOT NULL,
    rx_bytes INTEGER NOT NULL DEFAULT 0,
    tx_bytes INTEGER NOT NULL DEFAULT 0,
    rx_bps REAL NOT NULL DEFAULT 0,
    tx_bps REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_samples_peer_time ON traffic_samples(peer_id, sampled_at DESC);
