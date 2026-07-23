package wgbackend

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeBackend(t *testing.T) {
	b, err := NormalizeBackend("")
	require.NoError(t, err)
	require.Equal(t, BackendAuto, b)

	b, err = NormalizeBackend("wireguard-go")
	require.NoError(t, err)
	require.Equal(t, BackendUserspace, b)

	b, err = NormalizeBackend("amneziawg-go")
	require.NoError(t, err)
	require.Equal(t, BackendAmneziaGo, b)

	_, err = NormalizeBackend("nope")
	require.Error(t, err)
}

func TestNormalizeProtocol(t *testing.T) {
	p, err := NormalizeProtocol("amneziawg")
	require.NoError(t, err)
	require.Equal(t, ProtocolAWG, p)
}

func TestDefaultNoisePreset(t *testing.T) {
	p := DefaultNoisePreset()
	require.NoError(t, p.Validate())
	require.False(t, p.IsNeutral())
	require.NotEmpty(t, p.H1)
	require.NotEqual(t, p.H1, p.H2)
	require.NotEqual(t, p.H1, p.H3)
	require.NotEqual(t, p.H1, p.H4)
	require.NotZero(t, p.S1)
	require.NotZero(t, p.S2)
	require.NotEqual(t, p.S1+56, p.S2)
}

func TestNeutralAmneziaParams(t *testing.T) {
	p := NeutralAmneziaParams()
	require.True(t, p.IsNeutral())
	require.NoError(t, p.Validate())
}

func TestPairPortAndName(t *testing.T) {
	require.Equal(t, 51830, PairPort(51820))
	require.Equal(t, "awg0", DefaultPairName("wg0"))
	require.Equal(t, "wg-owire-awg", DefaultPairName("wg-owire-in"))
	require.Equal(t, "mesh0-awg", DefaultPairName("mesh0"))
}

func TestUAPILines(t *testing.T) {
	p := AmneziaParams{Jc: 4, H1: "123", S1: 10}
	lines := p.UAPILines()
	require.Contains(t, lines, "jc=4")
	require.Contains(t, lines, "h1=123")
	require.Contains(t, lines, "s1=10")
}
