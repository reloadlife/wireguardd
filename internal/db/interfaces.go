package db

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// ErrNotFound is returned when a row does not exist.
var ErrNotFound = errors.New("not found")

const ifaceSelect = `
SELECT id, name, private_key, public_key, listen_port, fwmark, mtu, table_mode, table_id,
       dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, public_endpoint,
       enabled, created_at, updated_at
FROM interfaces`

// CreateInterface inserts a new interface.
func (s *Store) CreateInterface(ctx context.Context, iface *Interface) error {
	now := nowRFC3339()
	if iface.TableMode == "" {
		iface.TableMode = "auto"
	}
	if iface.DNS == nil {
		iface.DNS = []string{}
	}
	if iface.Addresses == nil {
		iface.Addresses = []string{}
	}
	var tableID any
	if iface.TableID != nil {
		tableID = *iface.TableID
	}
	enabled := 0
	if iface.Enabled {
		enabled = 1
	}
	res, err := s.db.ExecContext(ctx, `
INSERT INTO interfaces (
  name, private_key, public_key, listen_port, fwmark, mtu, table_mode, table_id,
  dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, public_endpoint, enabled,
  created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		iface.Name, iface.PrivateKey, iface.PublicKey, iface.ListenPort, iface.FwMark, iface.MTU,
		iface.TableMode, tableID, encodeJSONList(iface.DNS), encodeJSONList(iface.Addresses),
		iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.DefaultKeepalive,
		iface.PublicEndpoint, enabled, now, now,
	)
	if err != nil {
		return fmt.Errorf("insert interface: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	iface.ID = id
	iface.CreatedAt = parseTime(now)
	iface.UpdatedAt = iface.CreatedAt
	return nil
}

// GetInterfaceByName loads an interface by name.
func (s *Store) GetInterfaceByName(ctx context.Context, name string) (*Interface, error) {
	row := s.db.QueryRowContext(ctx, ifaceSelect+` WHERE name = ?`, name)
	return scanInterface(row)
}

// GetInterfaceByID loads an interface by id.
func (s *Store) GetInterfaceByID(ctx context.Context, id int64) (*Interface, error) {
	row := s.db.QueryRowContext(ctx, ifaceSelect+` WHERE id = ?`, id)
	return scanInterface(row)
}

// ListInterfaces returns all interfaces ordered by name.
func (s *Store) ListInterfaces(ctx context.Context) ([]Interface, error) {
	rows, err := s.db.QueryContext(ctx, ifaceSelect+` ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Interface
	for rows.Next() {
		iface, err := scanInterfaceRows(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *iface)
	}
	return out, rows.Err()
}

// UpdateInterface updates mutable interface fields.
func (s *Store) UpdateInterface(ctx context.Context, iface *Interface) error {
	now := nowRFC3339()
	var tableID any
	if iface.TableID != nil {
		tableID = *iface.TableID
	}
	enabled := 0
	if iface.Enabled {
		enabled = 1
	}
	res, err := s.db.ExecContext(ctx, `
UPDATE interfaces SET
  private_key=?, public_key=?, listen_port=?, fwmark=?, mtu=?, table_mode=?, table_id=?,
  dns=?, addresses=?, pre_up=?, post_up=?, pre_down=?, post_down=?, default_keepalive=?,
  public_endpoint=?, enabled=?, updated_at=?
WHERE id=?`,
		iface.PrivateKey, iface.PublicKey, iface.ListenPort, iface.FwMark, iface.MTU,
		iface.TableMode, tableID, encodeJSONList(iface.DNS), encodeJSONList(iface.Addresses),
		iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.DefaultKeepalive,
		iface.PublicEndpoint, enabled, now, iface.ID,
	)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	iface.UpdatedAt = parseTime(now)
	return nil
}

// DeleteInterface removes an interface and its peers (cascade), and timeseries samples.
func (s *Store) DeleteInterface(ctx context.Context, name string) error {
	// Collect peer IDs first — samples live in a separate DB (no FK cascade).
	peers, _ := s.ListPeersByInterface(ctx, name)
	ids := make([]int64, 0, len(peers))
	for _, p := range peers {
		ids = append(ids, p.ID)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM interfaces WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	_ = s.DeletePeersSamples(ctx, ids)
	return nil
}

// ImportInterface upserts an interface and atomically replaces its peers.
// The whole import is one SQLite transaction so reconcile/API never observe a partial peer set.
// Timeseries rows for replaced peers are purged from timeseries.db after the state commit.
func (s *Store) ImportInterface(ctx context.Context, iface *Interface, peers []Peer) error {
	var stalePeerIDs []int64
	if existing, err := s.GetInterfaceByName(ctx, iface.Name); err == nil {
		old, _ := s.ListPeersByInterface(ctx, existing.Name)
		for _, p := range old {
			stalePeerIDs = append(stalePeerIDs, p.ID)
		}
	}
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		now := nowRFC3339()
		if iface.TableMode == "" {
			iface.TableMode = "auto"
		}
		if iface.DNS == nil {
			iface.DNS = []string{}
		}
		if iface.Addresses == nil {
			iface.Addresses = []string{}
		}
		var tableID any
		if iface.TableID != nil {
			tableID = *iface.TableID
		}
		enabled := 0
		if iface.Enabled {
			enabled = 1
		}

		var existingID int64
		err := tx.QueryRowContext(ctx, `SELECT id FROM interfaces WHERE name = ?`, iface.Name).Scan(&existingID)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			res, err := tx.ExecContext(ctx, `
INSERT INTO interfaces (
  name, private_key, public_key, listen_port, fwmark, mtu, table_mode, table_id,
  dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, public_endpoint, enabled,
  created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				iface.Name, iface.PrivateKey, iface.PublicKey, iface.ListenPort, iface.FwMark, iface.MTU,
				iface.TableMode, tableID, encodeJSONList(iface.DNS), encodeJSONList(iface.Addresses),
				iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.DefaultKeepalive,
				iface.PublicEndpoint, enabled, now, now,
			)
			if err != nil {
				return fmt.Errorf("insert interface: %w", err)
			}
			id, err := res.LastInsertId()
			if err != nil {
				return err
			}
			iface.ID = id
			iface.CreatedAt = parseTime(now)
			iface.UpdatedAt = iface.CreatedAt
		case err != nil:
			return err
		default:
			iface.ID = existingID
			res, err := tx.ExecContext(ctx, `
UPDATE interfaces SET
  private_key=?, public_key=?, listen_port=?, fwmark=?, mtu=?, table_mode=?, table_id=?,
  dns=?, addresses=?, pre_up=?, post_up=?, pre_down=?, post_down=?, default_keepalive=?,
  public_endpoint=?, enabled=?, updated_at=?
WHERE id=?`,
				iface.PrivateKey, iface.PublicKey, iface.ListenPort, iface.FwMark, iface.MTU,
				iface.TableMode, tableID, encodeJSONList(iface.DNS), encodeJSONList(iface.Addresses),
				iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.DefaultKeepalive,
				iface.PublicEndpoint, enabled, now, iface.ID,
			)
			if err != nil {
				return err
			}
			n, _ := res.RowsAffected()
			if n == 0 {
				return ErrNotFound
			}
			iface.UpdatedAt = parseTime(now)
		}

		if _, err := tx.ExecContext(ctx, `DELETE FROM peers WHERE interface_id = ?`, iface.ID); err != nil {
			return fmt.Errorf("clear peers: %w", err)
		}
		for i := range peers {
			p := &peers[i]
			p.InterfaceID = iface.ID
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
			res, err := tx.ExecContext(ctx, `
INSERT INTO peers (
  interface_id, public_key, preshared_key, client_private_key, name, notes, allowed_ips, assigned_ips,
  endpoint, persistent_keepalive, suspended, traffic_limit_bytes, expires_at, bandwidth_rx_bps,
  bandwidth_tx_bps, bandwidth_total_bps, rx_bytes_offset, tx_bytes_offset, first_handshake_at, last_handshake_at,
  connected_since, last_endpoint, last_rx_bytes, last_tx_bytes, last_rx_bps, last_tx_bps,
  tags, created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				p.InterfaceID, p.PublicKey, p.PresharedKey, p.ClientPrivateKey, p.Name, p.Notes,
				encodeJSONList(p.AllowedIPs), encodeJSONList(p.AssignedIPs),
				p.Endpoint, p.PersistentKeepalive, suspended, p.TrafficLimitBytes, p.ExpiresAt, p.BandwidthRxBps,
				p.BandwidthTxBps, p.BandwidthTotalBps, p.RxBytesOffset, p.TxBytesOffset, p.FirstHandshakeAt, p.LastHandshakeAt,
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
		}
		return nil
	})
	if err != nil {
		return err
	}
	_ = s.DeletePeersSamples(ctx, stalePeerIDs)
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanInterface(row scannable) (*Interface, error) {
	var (
		iface   Interface
		tableID sql.NullInt64
		dns     string
		addrs   string
		enabled int
		created string
		updated string
	)
	err := row.Scan(
		&iface.ID, &iface.Name, &iface.PrivateKey, &iface.PublicKey, &iface.ListenPort,
		&iface.FwMark, &iface.MTU, &iface.TableMode, &tableID, &dns, &addrs,
		&iface.PreUp, &iface.PostUp, &iface.PreDown, &iface.PostDown, &iface.DefaultKeepalive,
		&iface.PublicEndpoint, &enabled, &created, &updated,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if tableID.Valid {
		v := int(tableID.Int64)
		iface.TableID = &v
	}
	iface.DNS = decodeJSONList(dns)
	iface.Addresses = decodeJSONList(addrs)
	iface.Enabled = enabled != 0
	iface.CreatedAt = parseTime(created)
	iface.UpdatedAt = parseTime(updated)
	return &iface, nil
}

func scanInterfaceRows(rows *sql.Rows) (*Interface, error) {
	return scanInterface(rows)
}

// Ensure interface times use time package (silence unused if only parseTime used).
var _ = time.Time{}
