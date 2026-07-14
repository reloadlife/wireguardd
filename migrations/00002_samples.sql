-- +goose Up
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

-- +goose Down
DROP TABLE IF EXISTS traffic_samples;
