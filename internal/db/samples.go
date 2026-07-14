package db

import (
	"context"
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
