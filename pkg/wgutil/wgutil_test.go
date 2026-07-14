package wgutil

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/reloadlife/wireguardd/internal/crypto"
)

func TestNormalizeAndShort(t *testing.T) {
	kp, err := crypto.GenerateKeyPair()
	require.NoError(t, err)
	n, err := NormalizeKey(kp.PublicKey)
	require.NoError(t, err)
	require.Equal(t, kp.PublicKey, n)
	require.Contains(t, ShortKey(n), "…")

	esc := PathEscapeKey(n)
	back, err := PathUnescapeKey(esc)
	require.NoError(t, err)
	require.Equal(t, n, back)
}

func TestNormalizeInvalid(t *testing.T) {
	_, err := NormalizeKey("nope")
	require.Error(t, err)
}
