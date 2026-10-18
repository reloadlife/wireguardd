package wgbackend

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
)

// swift-mux same-port layout (one table for the whole host):
//
//	table inet wireguardd_mux
//	  chain prerouting   nat hook, jumps to classify_<public> per map
//	  chain classify_<p> stock-WireGuard-shaped first packet → return (stays on
//	                     the plain WG device that owns <p>); anything else →
//	                     redirect to the AWG device's listen port
//
// Only the first packet of a conntrack flow is classified; conntrack carries
// the rest and un-NATs replies back to <p>. The AWG device keeps its own port
// reachable directly (no input guard) so clients configured with PORT+10 keep
// working while configs move to the shared port.
//
// Stock WireGuard shapes (udp length includes the 8 B UDP header;
// @th,64,32 = first 4 payload bytes, little-endian message type):
//
//	initiation 148 B → udp length 156, 01 00 00 00
//	response    92 B → udp length 100, 02 00 00 00
//	cookie      64 B → udp length  72, 03 00 00 00
//	transport ≥ 32 B, 16-aligned → udp length ≥ 40, length & 15 == 8, 04 00 00 00
//
// Transport is matched on purpose: after a conntrack timeout a stock client's
// next packet is usually transport, not initiation. Mirrors services/swift
// mux/swift-mux (same classifier, minus the backend port moves).

const muxTable = "wireguardd_mux"

// MuxMap sends non-stock-WireGuard flows on PublicPort to AWGPort.
type MuxMap struct {
	PublicPort int
	AWGPort    int
	// Iface is the AWG interface name (rule comment only).
	Iface string
}

// ValidateMuxMaps rejects bad ports and overlaps between maps.
func ValidateMuxMaps(maps []MuxMap) error {
	public := map[int]bool{}
	backend := map[int]bool{}
	for _, m := range maps {
		if m.PublicPort < 1 || m.PublicPort > 65535 || m.AWGPort < 1 || m.AWGPort > 65535 {
			return fmt.Errorf("mux %s: bad port %d→%d", m.Iface, m.PublicPort, m.AWGPort)
		}
		if m.PublicPort == m.AWGPort {
			return fmt.Errorf("mux %s: public port equals awg port %d", m.Iface, m.AWGPort)
		}
		if public[m.PublicPort] {
			return fmt.Errorf("mux %s: public port %d used twice", m.Iface, m.PublicPort)
		}
		public[m.PublicPort] = true
		backend[m.AWGPort] = true
	}
	for p := range public {
		if backend[p] {
			return fmt.Errorf("mux: port %d is both a public and an awg port", p)
		}
	}
	return nil
}

// RenderMux returns the nft ruleset for maps (sorted by public port), or ""
// when maps is empty.
func RenderMux(maps []MuxMap) string {
	if len(maps) == 0 {
		return ""
	}
	sorted := append([]MuxMap(nil), maps...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].PublicPort < sorted[j].PublicPort })

	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", muxTable)
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, m := range sorted {
		fmt.Fprintf(&b, "    udp dport %d jump classify_%d\n", m.PublicPort, m.PublicPort)
	}
	b.WriteString("  }\n")
	for _, m := range sorted {
		p := m.PublicPort
		fmt.Fprintf(&b, "  chain classify_%d {\n", p)
		b.WriteString("    udp length 156 @th,64,32 0x01000000 counter return comment \"wg initiation\"\n")
		b.WriteString("    udp length 100 @th,64,32 0x02000000 counter return comment \"wg response\"\n")
		b.WriteString("    udp length 72 @th,64,32 0x03000000 counter return comment \"wg cookie\"\n")
		b.WriteString("    udp length >= 40 udp length & 0x000f == 0x0008 @th,64,32 0x04000000 counter return comment \"wg transport\"\n")
		// redirect needs a transport match in the same rule.
		fmt.Fprintf(&b, "    udp dport %d counter redirect to :%d comment %q\n", p, m.AWGPort, "awg "+sanitizeNFTIdent(m.Iface))
		b.WriteString("  }\n")
	}
	b.WriteString("}\n")
	return b.String()
}

// muxState remembers the last applied ruleset so reconcile does not rewrite
// the table every tick.
type muxState struct {
	mu      sync.Mutex
	applied string
}

// SyncMux installs (atomic replace) or removes the swift-mux table.
func (b *HostBackend) SyncMux(ctx context.Context, maps []MuxMap) error {
	if err := ValidateMuxMaps(maps); err != nil {
		return err
	}
	rules := RenderMux(maps)
	b.mux.mu.Lock()
	defer b.mux.mu.Unlock()

	_, listErr := b.runner.Run(ctx, "nft", "list", "table", nftFamily, muxTable)
	present := listErr == nil
	if rules == "" {
		b.mux.applied = ""
		if !present {
			return nil
		}
		if _, err := b.runner.Run(ctx, "nft", "delete", "table", nftFamily, muxTable); err != nil {
			return fmt.Errorf("mux remove: %w", err)
		}
		return nil
	}
	if present && rules == b.mux.applied {
		return nil
	}
	// Create-if-missing, delete, re-add: one nft transaction, so the port
	// is never left unclassified mid-update.
	script := fmt.Sprintf("table %s %s\ndelete table %s %s\n%s", nftFamily, muxTable, nftFamily, muxTable, rules)
	f, err := os.CreateTemp("", "wireguardd-mux-*.nft")
	if err != nil {
		return fmt.Errorf("mux temp file: %w", err)
	}
	defer func() { _ = os.Remove(f.Name()) }()
	if _, err := f.WriteString(script); err != nil {
		_ = f.Close()
		return fmt.Errorf("mux temp file: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("mux temp file: %w", err)
	}
	if _, err := b.runner.Run(ctx, "nft", "-f", f.Name()); err != nil {
		return fmt.Errorf("mux apply: %w", err)
	}
	b.mux.applied = rules
	return nil
}
