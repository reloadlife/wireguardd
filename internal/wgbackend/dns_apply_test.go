package wgbackend

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseDNSList(t *testing.T) {
	cfg := ParseDNSList([]string{
		"1.1.1.1",
		"2606:4700:4700::1111",
		"example.com",
		"~corp.local",
		"1.1.1.1", // dup
		"",
	})
	require.Equal(t, []string{"1.1.1.1", "2606:4700:4700::1111"}, cfg.Servers)
	require.Equal(t, []string{"example.com", "corp.local"}, cfg.Domains)
}

func TestSyncDNSResolvectl(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{
		runner:     rec,
		dnsBackend: DNSBackendResolvectl,
		dns:        newDNSState(),
	}
	ctx := context.Background()
	require.NoError(t, b.SyncDNS(ctx, DesiredInterface{
		Name:    "wg0",
		Enabled: true,
		DNS:     []string{"1.1.1.1", "8.8.8.8", "example.com"},
	}))
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "resolvectl dns wg0 1.1.1.1 8.8.8.8")
	require.Contains(t, joined, "resolvectl domain wg0 example.com")
	require.Contains(t, joined, "resolvectl default-route wg0 true")

	// idempotent — no extra apply when unchanged
	n := len(rec.cmds)
	require.NoError(t, b.SyncDNS(ctx, DesiredInterface{
		Name: "wg0", Enabled: true, DNS: []string{"1.1.1.1", "8.8.8.8", "example.com"},
	}))
	require.Equal(t, n, len(rec.cmds))

	// clear on empty / down
	require.NoError(t, b.SyncDNS(ctx, DesiredInterface{Name: "wg0", Enabled: false, DNS: []string{"1.1.1.1"}}))
	joined = strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "resolvectl revert wg0")
}

func TestSyncDNSResolvconf(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{
		runner:     rec,
		dnsBackend: DNSBackendResolvconf,
		dns:        newDNSState(),
	}
	ctx := context.Background()
	require.NoError(t, b.SyncDNS(ctx, DesiredInterface{
		Name:    "wg0",
		Enabled: true,
		DNS:     []string{"9.9.9.9", "search.example"},
	}))
	joined := strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "resolvconf -a tun.wg0")
	require.Contains(t, joined, "nameserver 9.9.9.9")
	require.Contains(t, joined, "search search.example")

	require.NoError(t, b.SyncDNS(ctx, DesiredInterface{Name: "wg0", Enabled: true}))
	joined = strings.Join(rec.joined(), "\n")
	require.Contains(t, joined, "resolvconf -d tun.wg0")
}

func TestSyncDNSNone(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, dnsBackend: DNSBackendNone, dns: newDNSState()}
	require.NoError(t, b.SyncDNS(context.Background(), DesiredInterface{
		Name: "wg0", Enabled: true, DNS: []string{"1.1.1.1"},
	}))
	require.Empty(t, rec.cmds)
}

func TestMockSyncDNS(t *testing.T) {
	m := NewMock()
	require.NoError(t, m.SyncDNS(context.Background(), DesiredInterface{
		Name: "wg0", Enabled: true, DNS: []string{"1.1.1.1", "corp.local"},
	}))
	require.Equal(t, []string{"1.1.1.1"}, m.DNSApplied["wg0"].Servers)
	require.Equal(t, []string{"corp.local"}, m.DNSApplied["wg0"].Domains)

	require.NoError(t, m.SyncDNS(context.Background(), DesiredInterface{Name: "wg0", Enabled: false}))
	_, ok := m.DNSApplied["wg0"]
	require.False(t, ok)
}

func TestClearInterfaceDNS(t *testing.T) {
	rec := &recordingRunner{}
	b := &HostBackend{runner: rec, dnsBackend: DNSBackendResolvectl, dns: newDNSState()}
	ctx := context.Background()
	require.NoError(t, b.SyncDNS(ctx, DesiredInterface{Name: "wg0", Enabled: true, DNS: []string{"1.1.1.1"}}))
	b.clearInterfaceDNS(ctx, "wg0")
	require.Contains(t, strings.Join(rec.joined(), "\n"), "resolvectl revert wg0")
}
