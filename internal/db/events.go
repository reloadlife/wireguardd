package db

import (
	"context"
	"fmt"
	"time"
)

// EventHook is invoked after a successful events row insert (webhooks, etc.).
type EventHook func(level, kind, iface, peerKey, message, meta string)

// SetEventHook registers an optional post-insert callback (e.g. webhook dispatcher).
func (s *Store) SetEventHook(hook EventHook) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.eventHook = hook
}

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
	s.mu.Lock()
	hook := s.eventHook
	s.mu.Unlock()
	if hook != nil {
		hook(level, kind, iface, peerKey, message, meta)
	}
	return nil
}

// PurgeEvents deletes events older than retention. Nothing reads events by
// time — ListEvents is the only reader and it takes the newest by id — so aged
// rows are pure growth: thr-respina reached 4.1M rows / 811 MB in two months.
//
// Deletes in batches like PurgeSamples so a first pass over a large backlog
// cannot grow the WAL past one batch.
func (s *Store) PurgeEvents(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339Nano)
	const batch = 5000
	var total int64
	for {
		res, err := s.db.ExecContext(ctx, `
DELETE FROM events WHERE id IN (
  SELECT id FROM events WHERE ts < ? LIMIT ?
)`, cutoff, batch)
		if err != nil {
			return total, fmt.Errorf("purge events: %w", err)
		}
		n, _ := res.RowsAffected()
		total += n
		if n < batch {
			return total, nil
		}
		if err := ctx.Err(); err != nil {
			return total, err
		}
	}
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
