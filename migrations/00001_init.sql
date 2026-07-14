-- +goose Up
CREATE TABLE IF NOT EXISTS interfaces (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    private_key TEXT NOT NULL,
    public_key TEXT NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 0,
    fwmark INTEGER NOT NULL DEFAULT 0,
    mtu INTEGER NOT NULL DEFAULT 0,
    table_mode TEXT NOT NULL DEFAULT 'auto',
    table_id INTEGER,
    dns TEXT NOT NULL DEFAULT '[]',
    addresses TEXT NOT NULL DEFAULT '[]',
    pre_up TEXT NOT NULL DEFAULT '',
    post_up TEXT NOT NULL DEFAULT '',
    pre_down TEXT NOT NULL DEFAULT '',
    post_down TEXT NOT NULL DEFAULT '',
    default_keepalive INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS peers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    interface_id INTEGER NOT NULL REFERENCES interfaces(id) ON DELETE CASCADE,
    public_key TEXT NOT NULL,
    preshared_key TEXT NOT NULL DEFAULT '',
    name TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    allowed_ips TEXT NOT NULL DEFAULT '[]',
    assigned_ips TEXT NOT NULL DEFAULT '[]',
    endpoint TEXT NOT NULL DEFAULT '',
    persistent_keepalive INTEGER NOT NULL DEFAULT 0,
    suspended INTEGER NOT NULL DEFAULT 0,
    traffic_limit_bytes INTEGER NOT NULL DEFAULT 0,
    bandwidth_rx_bps INTEGER NOT NULL DEFAULT 0,
    bandwidth_tx_bps INTEGER NOT NULL DEFAULT 0,
    rx_bytes_offset INTEGER NOT NULL DEFAULT 0,
    tx_bytes_offset INTEGER NOT NULL DEFAULT 0,
    first_handshake_at TEXT NOT NULL DEFAULT '',
    last_handshake_at TEXT NOT NULL DEFAULT '',
    connected_since TEXT NOT NULL DEFAULT '',
    last_endpoint TEXT NOT NULL DEFAULT '',
    last_rx_bytes INTEGER NOT NULL DEFAULT 0,
    last_tx_bytes INTEGER NOT NULL DEFAULT 0,
    last_rx_bps REAL NOT NULL DEFAULT 0,
    last_tx_bps REAL NOT NULL DEFAULT 0,
    tags TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE(interface_id, public_key)
);

CREATE INDEX IF NOT EXISTS idx_peers_interface ON peers(interface_id);
CREATE INDEX IF NOT EXISTS idx_peers_suspended ON peers(suspended);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    level TEXT NOT NULL DEFAULT 'info',
    kind TEXT NOT NULL DEFAULT 'system',
    interface TEXT NOT NULL DEFAULT '',
    peer_public_key TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts DESC);

-- +goose Down
DROP TABLE IF EXISTS events;
DROP TABLE IF EXISTS peers;
DROP TABLE IF EXISTS interfaces;
