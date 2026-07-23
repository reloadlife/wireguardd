-- +goose Up
-- Multi-backend WireGuard / AmneziaWG support.
-- backend: auto | kernel | userspace | amnezia_kernel | amnezia_go
-- protocol: wg | awg
-- amnezia_json: {"jc":0,"jmin":0,...,"h1":"...","i1":"..."}
ALTER TABLE interfaces ADD COLUMN backend TEXT NOT NULL DEFAULT 'auto';
ALTER TABLE interfaces ADD COLUMN protocol TEXT NOT NULL DEFAULT 'wg';
ALTER TABLE interfaces ADD COLUMN amnezia_json TEXT NOT NULL DEFAULT '';
-- Sibling pair linkage (plain WG ↔ AWG twin at port+10).
ALTER TABLE interfaces ADD COLUMN pair_name TEXT NOT NULL DEFAULT '';

-- +goose Down
ALTER TABLE interfaces DROP COLUMN pair_name;
ALTER TABLE interfaces DROP COLUMN amnezia_json;
ALTER TABLE interfaces DROP COLUMN protocol;
ALTER TABLE interfaces DROP COLUMN backend;
