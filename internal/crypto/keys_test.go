package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateKeyPair(t *testing.T) {
	kp, err := GenerateKeyPair()
	require.NoError(t, err)
	require.NotEmpty(t, kp.PrivateKey)
	require.NotEmpty(t, kp.PublicKey)

	pub, err := PublicFromPrivate(kp.PrivateKey)
	require.NoError(t, err)
	require.Equal(t, kp.PublicKey, pub)
}

func TestGeneratePSK(t *testing.T) {
	psk, err := GeneratePSK()
	require.NoError(t, err)
	require.NotEmpty(t, psk)
	_, err = ParseKey(psk)
	require.NoError(t, err)
}

func TestPublicFromPrivateInvalid(t *testing.T) {
	_, err := PublicFromPrivate("not-a-key")
	require.Error(t, err)
}
