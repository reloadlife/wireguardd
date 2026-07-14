-- +goose Up
-- Global time index for retention purge (DELETE ... WHERE sampled_at < ?).
CREATE INDEX IF NOT EXISTS idx_samples_time ON traffic_samples(sampled_at);

-- Covering-friendly peer+time index (ASC matches range scans for history).
CREATE INDEX IF NOT EXISTS idx_samples_peer_time_asc ON traffic_samples(peer_id, sampled_at);

-- +goose Down
DROP INDEX IF EXISTS idx_samples_peer_time_asc;
DROP INDEX IF EXISTS idx_samples_time;
