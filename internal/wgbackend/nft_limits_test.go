package wgbackend

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSanitizeNFTIdent(t *testing.T) {
	require.Equal(t, "wg0", sanitizeNFTIdent("wg0"))
	require.Equal(t, "wg_vpn", sanitizeNFTIdent("wg-vpn"))
	require.Equal(t, "n0iface", sanitizeNFTIdent("0iface"))
	require.Equal(t, "iface", sanitizeNFTIdent(""))
}

func TestFormatNFTRate(t *testing.T) {
	rate, burst := formatNFTRate(8_000_000) // 1 MiB/s
	require.Equal(t, "1 mbytes/second", rate)
	require.NotEmpty(t, burst)

	rate, burst = formatNFTRate(800_000) // 100 KiB/s
	require.Equal(t, "100 kbytes/second", rate)
	require.NotEmpty(t, burst)

	rate, _ = formatNFTRate(80) // 10 B/s
	require.Equal(t, "10 bytes/second", rate)
}

func TestSyncBandwidthNFT_TXRXIPv4IPv6(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{
		runner:           rec,
		bandwidthBackend: "nft",
		nft:              newNFTState(),
	}
	ctx := context.Background()
	peers := []DesiredPeer{{
		PublicKey:      "peerA===========================",
		AssignedIPs:    []string{"10.7.0.2", "fd00:7::2"},
		BandwidthTxBps: 8_000_000, // 1 mbyte/s
		BandwidthRxBps: 800_000,   // 100 kbyte/s
	}}
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", peers))

	joined := strings.Join(rec.joined(), "\n")
	// table + chains
	require.Contains(t, joined, "nft add table inet wireguardd_wg0")
	require.Contains(t, joined, "nft add chain inet wireguardd_wg0 rx")
	require.Contains(t, joined, "nft add chain inet wireguardd_wg0 tx")
	// hooks
	require.Contains(t, joined, "type filter hook input priority filter")
	require.Contains(t, joined, "type filter hook forward priority filter")
	require.Contains(t, joined, "type filter hook output priority filter")
	require.Contains(t, joined, "iifname != wg0 return")
	require.Contains(t, joined, "oifname != wg0 return")
	// RX rules (src)
	require.Contains(t, joined, "ip saddr 10.7.0.2 limit rate over 100 kbytes/second")
	require.Contains(t, joined, "ip6 saddr fd00:7::2 limit rate over 100 kbytes/second")
	// TX rules (dst)
	require.Contains(t, joined, "ip daddr 10.7.0.2 limit rate over 1 mbytes/second")
	require.Contains(t, joined, "ip6 daddr fd00:7::2 limit rate over 1 mbytes/second")
	require.Contains(t, joined, "drop comment")
}

func TestSyncBandwidthNFT_ClearsRemovedPeer(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{
		runner:           rec,
		bandwidthBackend: "nft",
		nft:              newNFTState(),
	}
	ctx := context.Background()
	p1 := DesiredPeer{
		PublicKey:      "peerA===========================",
		AssignedIPs:    []string{"10.7.0.2"},
		BandwidthTxBps: 8_000_000,
	}
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{p1}))

	// zero limits → delete table
	p1.BandwidthTxBps = 0
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{p1}))

	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "nft delete table inet wireguardd_wg0")
}

func TestSyncBandwidthNFT_RequiresHostIP(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "nft", nft: newNFTState()}
	err := b.SyncBandwidth(context.Background(), "wg0", []DesiredPeer{{
		PublicKey:      "peerB===========================",
		AllowedIPs:     []string{"0.0.0.0/0"},
		BandwidthTxBps: 1000,
	}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no host-sized")
}

func TestApplyBandwidthNFT_DoesNotClearOthers(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "nft", nft: newNFTState()}
	ctx := context.Background()
	a := DesiredPeer{PublicKey: "peerA===========================", AssignedIPs: []string{"10.0.0.2"}, BandwidthTxBps: 8e6}
	c := DesiredPeer{PublicKey: "peerC===========================", AssignedIPs: []string{"10.0.0.3"}, BandwidthTxBps: 16e6}
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{a, c}))

	a.BandwidthTxBps = 24e6
	require.NoError(t, b.ApplyBandwidth(ctx, "wg0", a))

	b.nft.mu.Lock()
	defer b.nft.mu.Unlock()
	st := b.nft.ifaces["wg0"]
	require.NotNil(t, st.peers[a.PublicKey])
	require.NotNil(t, st.peers[c.PublicKey], "peer C must remain after single ApplyBandwidth")
	require.Equal(t, int64(24e6), st.peers[a.PublicKey].txBps)

	// last flush+rules should still include both peer IPs
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "ip daddr 10.0.0.2")
	require.Contains(t, joined, "ip daddr 10.0.0.3")
}

func TestClearInterfaceNFT(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "nft", nft: newNFTState()}
	ctx := context.Background()
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{{
		PublicKey: "peerA===========================", AssignedIPs: []string{"10.0.0.2"}, BandwidthTxBps: 8e6,
	}}))
	b.clearInterfaceTC(ctx, "wg0")
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "nft delete table inet wireguardd_wg0")
}

func TestSyncBandwidthUnsupported(t *testing.T) {
	b := &HostBackend{runner: &recordingRunner{}, bandwidthBackend: "foo"}
	err := b.SyncBandwidth(context.Background(), "wg0", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unsupported")
}

func TestNFTTableNameHyphenIface(t *testing.T) {
	require.Equal(t, "wireguardd_wg_office", nftTableName("wg-office"))
}
