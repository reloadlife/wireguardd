package db

import (
	"context"
	"fmt"
	"time"
)

// AddEvent inserts an event record.
func (s *Store) AddEvent(ctx context.Context, level, kind, iface, peerKey, message, meta string) error {
	if meta == "" {
		meta = "{}"
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO events (ts, level, kind, interface, peer_public_key, message, meta)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
		nowRFC3339(), level, kind, iface, peerKey, message, meta,
	)
	if err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	return nil
}

// ListEvents returns the most recent events.
func (s *Store) ListEvents(ctx context.Context, limit int) ([]Event, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, ts, level, kind, interface, peer_public_key, message, meta
FROM events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Event
	for rows.Next() {
		var e Event
		var ts string
		if err := rows.Scan(&e.ID, &ts, &e.Level, &e.Kind, &e.Interface, &e.PeerPublicKey, &e.Message, &e.Meta); err != nil {
			return nil, err
		}
		e.TS = parseTime(ts)
		if e.TS.IsZero() {
			e.TS = time.Now().UTC()
		}
		out = append(out, e)
	}
	return out, rows.Err()
}
