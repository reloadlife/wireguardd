package wgbackend

import (
	"context"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
)

// recordingRunner captures tc/ip commands for assertions.
type recordingRunner struct {
	mu   sync.Mutex
	cmds [][]string
	// failSubstr if non-empty causes matching commands to fail
	failSubstr string
}

func (r *recordingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	full := append([]string{name}, args...)
	r.cmds = append(r.cmds, full)
	joined := strings.Join(full, " ")
	if r.failSubstr != "" && strings.Contains(joined, r.failSubstr) {
		return "", errString("simulated fail: " + joined)
	}
	// Simulate "File exists" for second root add
	if name == "tc" && len(args) > 2 && args[0] == "qdisc" && args[1] == "add" {
		count := 0
		for _, c := range r.cmds {
			if len(c) > 2 && c[0] == "tc" && c[1] == "qdisc" && c[2] == "add" && contains(c, args[4]) {
				count++
			}
		}
		if count > 1 && contains(args, "root") {
			return "", errString("File exists")
		}
	}
	return "", nil
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

type errString string

func (e errString) Error() string { return string(e) }

func (r *recordingRunner) joined() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.cmds))
	for i, c := range r.cmds {
		out[i] = strings.Join(c, " ")
	}
	return out
}

func TestFormatTCRate(t *testing.T) {
	require.Equal(t, "1mbit", formatTCRate(1_000_000))
	require.Equal(t, "500kbit", formatTCRate(500_000))
	require.Equal(t, "1234bit", formatTCRate(1234))
}

func TestPeerHostIPs(t *testing.T) {
	ips := peerHostIPs(DesiredPeer{
		AssignedIPs: []string{"10.0.0.2", "fd00::2/128"},
		AllowedIPs:  []string{"0.0.0.0/0", "10.0.0.3/32"},
	})
	require.Equal(t, []string{"10.0.0.2", "fd00::2"}, ips)

	// fallback to host AllowedIPs only
	ips = peerHostIPs(DesiredPeer{
		AllowedIPs: []string{"0.0.0.0/0", "10.8.0.5/32", "2001:db8::5/128"},
	})
	require.Equal(t, []string{"10.8.0.5", "2001:db8::5"}, ips)

	// no broad prefixes alone
	ips = peerHostIPs(DesiredPeer{AllowedIPs: []string{"10.0.0.0/24"}})
	require.Empty(t, ips)
}

func TestSyncBandwidthTXRXIPv4IPv6(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{
		runner:           rec,
		bandwidthBackend: "tc",
		tc:               newTCState(),
	}
	ctx := context.Background()
	peers := []DesiredPeer{{
		PublicKey:      "peerA===========================",
		AssignedIPs:    []string{"10.7.0.2", "fd00:7::2"},
		BandwidthTxBps: 2_000_000, // 2 mbit
		BandwidthRxBps: 1_000_000, // 1 mbit
	}}
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", peers))

	cmds := rec.joined()
	joined := strings.Join(cmds, "\n")

	// root HTB + default class
	require.Contains(t, joined, "tc qdisc add dev wg0 root handle 1: htb default 1")
	require.Contains(t, joined, "tc class replace dev wg0 parent 1: classid 1:1 htb rate 100gbit")
	// ingress
	require.Contains(t, joined, "tc qdisc add dev wg0 handle ffff: ingress")
	// TX class rate 2mbit
	require.Contains(t, joined, "htb rate 2mbit ceil 2mbit")
	// IPv4 dst filter (egress)
	require.Contains(t, joined, "match ip dst 10.7.0.2/32")
	// IPv6 dst filter
	require.Contains(t, joined, "match ip6 dst fd00:7::2/128")
	// RX police src
	require.Contains(t, joined, "match ip src 10.7.0.2/32")
	require.Contains(t, joined, "match ip6 src fd00:7::2/128")
	require.Contains(t, joined, "action police rate 1mbit")
}

func TestSyncBandwidthClearsRemovedPeer(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{
		runner:           rec,
		bandwidthBackend: "tc",
		tc:               newTCState(),
	}
	ctx := context.Background()
	p1 := DesiredPeer{
		PublicKey:      "peerA===========================",
		AssignedIPs:    []string{"10.7.0.2"},
		BandwidthTxBps: 1_000_000,
	}
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{p1}))

	// clear limits
	p1.BandwidthTxBps = 0
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{p1}))

	cmds := rec.joined()
	// should have class del or filter del
	var sawDel bool
	for _, c := range cmds {
		if strings.Contains(c, "class del") || strings.Contains(c, "filter del") {
			sawDel = true
			break
		}
	}
	require.True(t, sawDel, "expected cleanup commands, got: %v", cmds)
}

func TestSyncBandwidthNoneBackend(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "none", tc: newTCState()}
	err := b.SyncBandwidth(context.Background(), "wg0", []DesiredPeer{{
		PublicKey: "x", AssignedIPs: []string{"10.0.0.2"}, BandwidthTxBps: 1000,
	}})
	require.NoError(t, err)
	require.Empty(t, rec.cmds)
}

func TestSyncBandwidthRequiresHostIP(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "tc", tc: newTCState()}
	err := b.SyncBandwidth(context.Background(), "wg0", []DesiredPeer{{
		PublicKey:      "peerB===========================",
		AllowedIPs:     []string{"0.0.0.0/0"},
		BandwidthTxBps: 1000,
	}})
	require.Error(t, err)
	require.Contains(t, err.Error(), "no host-sized")
}

func TestApplyBandwidthDoesNotClearOthers(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "tc", tc: newTCState()}
	ctx := context.Background()
	a := DesiredPeer{PublicKey: "peerA===========================", AssignedIPs: []string{"10.0.0.2"}, BandwidthTxBps: 1e6}
	c := DesiredPeer{PublicKey: "peerC===========================", AssignedIPs: []string{"10.0.0.3"}, BandwidthTxBps: 2e6}
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{a, c}))

	// single-peer apply for A only
	a.BandwidthTxBps = 3e6
	require.NoError(t, b.ApplyBandwidth(ctx, "wg0", a))

	b.tc.mu.Lock()
	defer b.tc.mu.Unlock()
	st := b.tc.ifaces["wg0"]
	require.NotNil(t, st.peers[a.PublicKey])
	require.NotNil(t, st.peers[c.PublicKey], "peer C must remain after single ApplyBandwidth")
	require.Equal(t, int64(3e6), st.peers[a.PublicKey].txBps)
}

func TestMockSyncBandwidth(t *testing.T) {
	m := NewMock()
	ctx := context.Background()
	_ = m.EnsureInterface(ctx, DesiredInterface{Name: "wg0", Enabled: true})
	require.NoError(t, m.SyncBandwidth(ctx, "wg0", []DesiredPeer{
		{PublicKey: "p1", BandwidthTxBps: 100, AssignedIPs: []string{"10.0.0.2"}},
		{PublicKey: "p2", BandwidthRxBps: 0, BandwidthTxBps: 0},
	}))
	require.Len(t, m.Bandwidth["wg0"], 1)
	require.Equal(t, int64(100), m.Bandwidth["wg0"]["p1"].BandwidthTxBps)
}

func TestClearInterfaceTC(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, bandwidthBackend: "tc", tc: newTCState()}
	ctx := context.Background()
	require.NoError(t, b.SyncBandwidth(ctx, "wg0", []DesiredPeer{{
		PublicKey: "peerA===========================", AssignedIPs: []string{"10.0.0.2"}, BandwidthTxBps: 1e6,
	}}))
	b.clearInterfaceTC(ctx, "wg0")
	cmds := rec.joined()
	require.Contains(t, strings.Join(cmds, "\n"), "qdisc del dev wg0 root")
	require.Contains(t, strings.Join(cmds, "\n"), "qdisc del dev wg0 ingress")
}
