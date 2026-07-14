package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// InsertSample stores a traffic sample.
func (s *Store) InsertSample(ctx context.Context, sample TrafficSample) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO traffic_samples (peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps)
VALUES (?, ?, ?, ?, ?, ?)`,
		sample.PeerID, sample.SampledAt.UTC().Format(time.RFC3339Nano),
		sample.RxBytes, sample.TxBytes, sample.RxBps, sample.TxBps,
	)
	if err != nil {
		return fmt.Errorf("insert sample: %w", err)
	}
	return nil
}

// PurgeSamples older than retention.
func (s *Store) PurgeSamples(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-olderThan).Format(time.RFC3339Nano)
	res, err := s.db.ExecContext(ctx, `DELETE FROM traffic_samples WHERE sampled_at < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// SampleAtOrBefore returns the newest sample at or before t for a peer.
func (s *Store) SampleAtOrBefore(ctx context.Context, peerID int64, t time.Time) (*TrafficSample, error) {
	row := s.db.QueryRowContext(ctx, `
SELECT id, peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps
FROM traffic_samples
WHERE peer_id = ? AND sampled_at <= ?
ORDER BY sampled_at DESC
LIMIT 1`, peerID, t.UTC().Format(time.RFC3339Nano))
	return scanSample(row)
}

// ListPeerSamples returns samples in [from, to] ascending by time.
func (s *Store) ListPeerSamples(ctx context.Context, peerID int64, from, to time.Time, limit int) ([]TrafficSample, error) {
	if limit <= 0 {
		limit = 1000
	}
	if limit > 10000 {
		limit = 10000
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, peer_id, sampled_at, rx_bytes, tx_bytes, rx_bps, tx_bps
FROM traffic_samples
WHERE peer_id = ? AND sampled_at >= ? AND sampled_at <= ?
ORDER BY sampled_at ASC
LIMIT ?`,
		peerID,
		from.UTC().Format(time.RFC3339Nano),
		to.UTC().Format(time.RFC3339Nano),
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []TrafficSample
	for rows.Next() {
		var sm TrafficSample
		var ts string
		if err := rows.Scan(&sm.ID, &sm.PeerID, &ts, &sm.RxBytes, &sm.TxBytes, &sm.RxBps, &sm.TxBps); err != nil {
			return nil, err
		}
		sm.SampledAt = parseTime(ts)
		out = append(out, sm)
	}
	return out, rows.Err()
}

// PeerWindowBaselines returns the sample at-or-before each cutoff time.
// keys of cutoffs become keys of the result map.
func (s *Store) PeerWindowBaselines(ctx context.Context, peerID int64, cutoffs map[string]time.Time) (map[string]TrafficSample, error) {
	out := make(map[string]TrafficSample, len(cutoffs))
	for name, t := range cutoffs {
		sm, err := s.SampleAtOrBefore(ctx, peerID, t)
		if err != nil {
			if err == sql.ErrNoRows || err == ErrNotFound {
				continue
			}
			return nil, err
		}
		if sm != nil {
			out[name] = *sm
		}
	}
	return out, nil
}

func scanSample(row *sql.Row) (*TrafficSample, error) {
	var sm TrafficSample
	var ts string
	err := row.Scan(&sm.ID, &sm.PeerID, &ts, &sm.RxBytes, &sm.TxBytes, &sm.RxBps, &sm.TxBps)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sm.SampledAt = parseTime(ts)
	return &sm, nil
}
