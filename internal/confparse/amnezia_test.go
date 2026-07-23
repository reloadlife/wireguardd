package confparse

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseRenderAmnezia(t *testing.T) {
	in := `[Interface]
# Backend = amnezia_kernel
# Protocol = awg
PrivateKey = aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=
ListenPort = 51820
Jc = 4
Jmin = 8
Jmax = 80
S1 = 20
S2 = 30
H1 = 111
H2 = 222
H3 = 333
H4 = 444

[Peer]
PublicKey = bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb=
AllowedIPs = 10.0.0.2/32
`
	cfg, err := Parse(in)
	require.NoError(t, err)
	require.Equal(t, 4, cfg.Interface.Jc)
	require.Equal(t, 20, cfg.Interface.S1)
	require.Equal(t, "111", cfg.Interface.H1)
	require.Equal(t, "amnezia_kernel", cfg.Interface.Backend)
	require.Equal(t, "awg", cfg.Interface.Protocol)
	require.True(t, cfg.Interface.HasAmnezia())

	out := Render(cfg)
	require.Contains(t, out, "Jc = 4")
	require.Contains(t, out, "H1 = 111")
	require.Contains(t, out, "# Protocol = awg")
	// Round-trip
	cfg2, err := Parse(out)
	require.NoError(t, err)
	require.Equal(t, cfg.Interface.H4, cfg2.Interface.H4)
	require.True(t, strings.Contains(out, "S2 = 30"))
}
