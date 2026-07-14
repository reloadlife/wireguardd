package confparse

import (
	"testing"

	"github.com/stretchr/testify/require"
)

const sample = `[Interface]
PrivateKey = cGFzc3dvcmQxMjM0NTY3ODkwMTIzNDU2Nzg5MDEyMzQ=
Address = 10.0.0.1/24, fd00::1/64
ListenPort = 51820
DNS = 1.1.1.1, 2606:4700:4700::1111
MTU = 1420
Table = auto
FwMark = 51820
PostUp = iptables -A FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = dGVzdHBheWxvYWRrZXl0ZXN0cGF5bG9hZGs=
PresharedKey = cHNrMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3OA==
AllowedIPs = 10.0.0.2/32, fd00::2/128
Endpoint = 203.0.113.1:51820
PersistentKeepalive = 25
`

func TestParseAndRenderRoundTrip(t *testing.T) {
	cfg, err := Parse(sample)
	require.NoError(t, err)
	require.Equal(t, 51820, cfg.Interface.ListenPort)
	require.Equal(t, []string{"10.0.0.1/24", "fd00::1/64"}, cfg.Interface.Address)
	require.Equal(t, []string{"1.1.1.1", "2606:4700:4700::1111"}, cfg.Interface.DNS)
	require.Len(t, cfg.Peers, 1)
	require.Equal(t, 25, cfg.Peers[0].PersistentKeepalive)
	require.Equal(t, "203.0.113.1:51820", cfg.Peers[0].Endpoint)

	out := Render(cfg)
	cfg2, err := Parse(out)
	require.NoError(t, err)
	require.Equal(t, cfg.Interface.PrivateKey, cfg2.Interface.PrivateKey)
	require.Equal(t, cfg.Interface.ListenPort, cfg2.Interface.ListenPort)
	require.Equal(t, cfg.Peers[0].PublicKey, cfg2.Peers[0].PublicKey)
	require.Equal(t, cfg.Peers[0].AllowedIPs, cfg2.Peers[0].AllowedIPs)
}

func TestParseMissingPrivateKey(t *testing.T) {
	// Incomplete confs are allowed (adopt path); PrivateKey may be empty.
	cfg, err := Parse("[Interface]\nListenPort = 1\n")
	require.NoError(t, err)
	require.Empty(t, cfg.Interface.PrivateKey)
	require.Equal(t, 1, cfg.Interface.ListenPort)
}

func TestParseCommentsAndBlank(t *testing.T) {
	cfg, err := Parse(`
# comment
[Interface]
PrivateKey = abc
; another

# Name = alice
# Address = 10.0.0.2/24
# TrafficLimit = 1000
[Peer]
PublicKey = def
AllowedIPs = 0.0.0.0/0
`)
	require.NoError(t, err)
	require.Equal(t, "abc", cfg.Interface.PrivateKey)
	require.Len(t, cfg.Peers, 1)
	require.Equal(t, "alice", cfg.Peers[0].Name)
	require.Equal(t, "10.0.0.2/24", cfg.Peers[0].Address)
	require.Equal(t, int64(1000), cfg.Peers[0].TrafficLimit)

	out := Render(cfg)
	require.Contains(t, out, "# Name = alice")
	require.Contains(t, out, "# TrafficLimit = 1000")
	cfg2, err := Parse(out)
	require.NoError(t, err)
	require.Equal(t, "alice", cfg2.Peers[0].Name)
}
