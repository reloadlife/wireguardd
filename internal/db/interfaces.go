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
  dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, enabled,
  created_at, updated_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		iface.Name, iface.PrivateKey, iface.PublicKey, iface.ListenPort, iface.FwMark, iface.MTU,
		iface.TableMode, tableID, encodeJSONList(iface.DNS), encodeJSONList(iface.Addresses),
		iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.DefaultKeepalive, enabled,
		now, now,
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
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, private_key, public_key, listen_port, fwmark, mtu, table_mode, table_id,
       dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, enabled,
       created_at, updated_at
FROM interfaces WHERE name = ?`, name)
	return scanInterface(row)
}

// GetInterfaceByID loads an interface by id.
func (s *Store) GetInterfaceByID(ctx context.Context, id int64) (*Interface, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, name, private_key, public_key, listen_port, fwmark, mtu, table_mode, table_id,
       dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, enabled,
       created_at, updated_at
FROM interfaces WHERE id = ?`, id)
	return scanInterface(row)
}

// ListInterfaces returns all interfaces ordered by name.
func (s *Store) ListInterfaces(ctx context.Context) ([]Interface, error) {
	rows, err := s.db.QueryContext(ctx, `
SELECT id, name, private_key, public_key, listen_port, fwmark, mtu, table_mode, table_id,
       dns, addresses, pre_up, post_up, pre_down, post_down, default_keepalive, enabled,
       created_at, updated_at
FROM interfaces ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
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
  enabled=?, updated_at=?
WHERE id=?`,
		iface.PrivateKey, iface.PublicKey, iface.ListenPort, iface.FwMark, iface.MTU,
		iface.TableMode, tableID, encodeJSONList(iface.DNS), encodeJSONList(iface.Addresses),
		iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown, iface.DefaultKeepalive,
		enabled, now, iface.ID,
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

// DeleteInterface removes an interface and its peers (cascade).
func (s *Store) DeleteInterface(ctx context.Context, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM interfaces WHERE name = ?`, name)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

type scannable interface {
	Scan(dest ...any) error
}

func scanInterface(row scannable) (*Interface, error) {
	var (
		iface    Interface
		tableID  sql.NullInt64
		dns      string
		addrs    string
		enabled  int
		created  string
		updated  string
	)
	err := row.Scan(
		&iface.ID, &iface.Name, &iface.PrivateKey, &iface.PublicKey, &iface.ListenPort,
		&iface.FwMark, &iface.MTU, &iface.TableMode, &tableID, &dns, &addrs,
		&iface.PreUp, &iface.PostUp, &iface.PreDown, &iface.PostDown, &iface.DefaultKeepalive,
		&enabled, &created, &updated,
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
