package db

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPurgeEventsKeepsRetentionWindow(t *testing.T) {
	s := openTestDB(t)
	ctx := context.Background()

	// AddEvent stamps rows with time.Now(), so backdate them afterwards: the
	// cutoff is what is under test, not the insert path.
	for i := 0; i < 12; i++ {
		require.NoError(t, s.AddEvent(ctx, "info", "audit", "wg0", "", "old", ""))
	}
	old := time.Now().UTC().Add(-60 * 24 * time.Hour).Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `UPDATE events SET ts = ?`, old)
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		require.NoError(t, s.AddEvent(ctx, "info", "audit", "wg0", "", "fresh", ""))
	}

	n, err := s.PurgeEvents(ctx, 30*24*time.Hour)
	require.NoError(t, err)
	require.EqualValues(t, 12, n)

	left, err := s.ListEvents(ctx, 100)
	require.NoError(t, err)
	require.Len(t, left, 3)
	for _, e := range left {
		require.Equal(t, "fresh", e.Message)
	}
}
