-- +goose Up
-- Peer policy: optional expiry and combined bandwidth cap (bytes/sec).
ALTER TABLE peers ADD COLUMN expires_at TEXT NOT NULL DEFAULT '';
ALTER TABLE peers ADD COLUMN bandwidth_total_bps INTEGER NOT NULL DEFAULT 0;

-- +goose Down
-- SQLite cannot DROP COLUMN on older versions; no-op for down.
