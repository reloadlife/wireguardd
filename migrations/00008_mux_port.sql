-- +goose Up
-- swift-mux same-port mode: an AWG interface with mux_port > 0 also receives
-- every non-stock-WireGuard flow that arrives on UDP mux_port (the plain WG
-- twin keeps listening there). 0 = off.
ALTER TABLE interfaces ADD COLUMN mux_port INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE interfaces DROP COLUMN mux_port;
