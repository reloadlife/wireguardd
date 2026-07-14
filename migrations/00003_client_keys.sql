-- +goose Up
ALTER TABLE interfaces ADD COLUMN public_endpoint TEXT NOT NULL DEFAULT '';
ALTER TABLE peers ADD COLUMN client_private_key TEXT NOT NULL DEFAULT '';

-- +goose Down
-- SQLite cannot drop columns portably; leave no-op for down.
SELECT 1;
