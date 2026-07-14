package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// CreatePeer inserts a peer.
func (s *Store) CreatePeer(ctx context.Context, p *Peer) error {
	now := nowRFC3339()
	if p.AllowedIPs == nil {
		p.AllowedIPs = []string{}
	}
	if p.AssignedIPs == nil {
		p.AssignedIPs = []string{}
	}
	if p.Tags == nil {
		p.Tags = []string{}
	}
	suspended := 0
	if p.Suspended {
		suspended = 1
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO peers (
  interface_id, public_key, preshared_key, client_private_key, name, notes, allowed_ips, assigned_ips,
  endpoint, persistent_keepalive, suspended, traffic_limit_bytes, bandwidth_rx_bps,
  bandwidth_tx_bps, rx_bytes_offset, tx_bytes_offset, first_handshake_at, last_handshake_at,
  connected_since, last_endpoint, last_rx_bytes, last_tx_bytes, last_rx_bps, last_tx_bps,
  tags, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.InterfaceID, p.PublicKey, p.PresharedKey, p.ClientPrivateKey, p.Name, p.Notes,
		encodeJSONList(p.AllowedIPs), encodeJSONList(p.AssignedIPs),
		p.Endpoint, p.PersistentKeepalive, suspended, p.TrafficLimitBytes, p.BandwidthRxBps,
		p.BandwidthTxBps, p.RxBytesOffset, p.TxBytesOffset, p.FirstHandshakeAt, p.LastHandshakeAt,
		p.ConnectedSince, p.LastEndpoint, p.LastRxBytes, p.LastTxBytes, p.LastRxBps, p.LastTxBps,
		encodeJSONList(p.Tags), now, now,
	)
	if err != nil {
		return fmt.Errorf("insert peer: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	p.ID = id
	p.CreatedAt = parseTime(now)
	p.UpdatedAt = p.CreatedAt
	return nil
}

// GetPeer loads a peer by interface name + public key.
func (s *Store) GetPeer(ctx context.Context, ifaceName, publicKey string) (*Peer, error) {
	row := s.db.QueryRowContext(ctx, peerSelect+`
FROM peers p
JOIN interfaces i ON i.id = p.interface_id
WHERE i.name = ? AND p.public_key = ?`, ifaceName, publicKey)
	return scanPeer(row)
}

// ListPeersByInterface lists peers for an interface name.
func (s *Store) ListPeersByInterface(ctx context.Context, ifaceName string) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, peerSelect+`
FROM peers p
JOIN interfaces i ON i.id = p.interface_id
WHERE i.name = ?
ORDER BY p.name, p.public_key`, ifaceName)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanPeers(rows)
}

// ListAllPeers lists all peers.
func (s *Store) ListAllPeers(ctx context.Context) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, peerSelect+`
FROM peers p
JOIN interfaces i ON i.id = p.interface_id
ORDER BY i.name, p.name, p.public_key`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	return scanPeers(rows)
}

// UpdatePeer updates peer configuration and policy.
// Runtime stats (handshake, endpoint, counters, rates) are owned by UpdatePeerStats.
// PublicKey is updated when changed (client key rotation).
func (s *Store) UpdatePeer(ctx context.Context, p *Peer) error {
	now := nowRFC3339()
	suspended := 0
	if p.Suspended {
		suspended = 1
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE peers SET
  public_key=?, preshared_key=?, client_private_key=?, name=?, notes=?, allowed_ips=?, assigned_ips=?, endpoint=?,
  persistent_keepalive=?, suspended=?, traffic_limit_bytes=?, bandwidth_rx_bps=?,
  bandwidth_tx_bps=?, rx_bytes_offset=?, tx_bytes_offset=?, tags=?, updated_at=?
WHERE id=?`,
		p.PublicKey, p.PresharedKey, p.ClientPrivateKey, p.Name, p.Notes, encodeJSONList(p.AllowedIPs), encodeJSONList(p.AssignedIPs),
		p.Endpoint, p.PersistentKeepalive, suspended, p.TrafficLimitBytes, p.BandwidthRxBps,
		p.BandwidthTxBps, p.RxBytesOffset, p.TxBytesOffset,
		encodeJSONList(p.Tags), now, p.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	p.UpdatedAt = parseTime(now)
	return nil
}

// DeletePeer removes a peer and its timeseries samples.
func (s *Store) DeletePeer(ctx context.Context, ifaceName, publicKey string) error {
	peer, err := s.GetPeer(ctx, ifaceName, publicKey)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, peer.ID)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	_ = s.DeletePeerSamples(ctx, peer.ID)
	return nil
}

// UpdatePeerStats updates observed traffic/handshake fields.
func (s *Store) UpdatePeerStats(ctx context.Context, p *Peer) error {
	_, err := s.db.ExecContext(ctx, `
UPDATE peers SET
  first_handshake_at=?, last_handshake_at=?, connected_since=?, last_endpoint=?,
  last_rx_bytes=?, last_tx_bytes=?, last_rx_bps=?, last_tx_bps=?, updated_at=?
WHERE id=?`,
		p.FirstHandshakeAt, p.LastHandshakeAt, p.ConnectedSince, p.LastEndpoint,
		p.LastRxBytes, p.LastTxBytes, p.LastRxBps, p.LastTxBps, nowRFC3339(), p.ID,
	)
	return err
}

// SetPeerSuspended sets the suspended flag.
func (s *Store) SetPeerSuspended(ctx context.Context, id int64, suspended bool) error {
	v := 0
	if suspended {
		v = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE peers SET suspended=?, updated_at=? WHERE id=?`, v, nowRFC3339(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// SoftResetPeerTraffic sets offsets to current kernel counters.
func (s *Store) SoftResetPeerTraffic(ctx context.Context, id int64, rx, tx int64) error {
	res, err := s.db.ExecContext(ctx, `
UPDATE peers SET rx_bytes_offset=?, tx_bytes_offset=?, updated_at=? WHERE id=?`,
		rx, tx, nowRFC3339(), id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

const peerSelect = `
SELECT p.id, p.interface_id, i.name, p.public_key, p.preshared_key, p.client_private_key, p.name, p.notes,
       p.allowed_ips, p.assigned_ips, p.endpoint, p.persistent_keepalive, p.suspended,
       p.traffic_limit_bytes, p.bandwidth_rx_bps, p.bandwidth_tx_bps, p.rx_bytes_offset,
       p.tx_bytes_offset, p.first_handshake_at, p.last_handshake_at, p.connected_since,
       p.last_endpoint, p.last_rx_bytes, p.last_tx_bytes, p.last_rx_bps, p.last_tx_bps,
       p.tags, p.created_at, p.updated_at
`

func scanPeer(row scannable) (*Peer, error) {
	var (
		p         Peer
		allowed   string
		assigned  string
		tags      string
		suspended int
		created   string
		updated   string
	)
	err := row.Scan(
		&p.ID, &p.InterfaceID, &p.InterfaceName, &p.PublicKey, &p.PresharedKey, &p.ClientPrivateKey,
		&p.Name, &p.Notes,
		&allowed, &assigned, &p.Endpoint, &p.PersistentKeepalive, &suspended,
		&p.TrafficLimitBytes, &p.BandwidthRxBps, &p.BandwidthTxBps, &p.RxBytesOffset,
		&p.TxBytesOffset, &p.FirstHandshakeAt, &p.LastHandshakeAt, &p.ConnectedSince,
		&p.LastEndpoint, &p.LastRxBytes, &p.LastTxBytes, &p.LastRxBps, &p.LastTxBps,
		&tags, &created, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	p.AllowedIPs = decodeJSONList(allowed)
	p.AssignedIPs = decodeJSONList(assigned)
	p.Tags = decodeJSONList(tags)
	p.Suspended = suspended != 0
	p.CreatedAt = parseTime(created)
	p.UpdatedAt = parseTime(updated)
	return &p, nil
}

func scanPeers(rows *sql.Rows) ([]Peer, error) {
	var out []Peer
	for rows.Next() {
		p, err := scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}
