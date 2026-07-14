package wgbackend

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode"
)

// nftables bandwidth layout (per WireGuard iface):
//
//	table inet wireguardd_<iface>
//	  hook chains attach to input / forward / output and jump to:
//	    chain rx  — match iifname + peer source IPs  (peer → host / forward)
//	    chain tx  — match oifname + peer dest IPs    (host / forward → peer)
//
// RX/TX limits use `limit rate over <bytes/sec> burst … drop` so traffic above
// the configured bit/s cap is dropped. Independent IPv4 and IPv6 rules are
// installed for each host-sized tunnel address.
//
// Full clear of an interface is `nft delete table inet wireguardd_<iface>`.

const (
	nftFamily     = "inet"
	nftTablePref  = "wireguardd_"
	nftChainRX    = "rx"
	nftChainTX    = "tx"
	nftPrioFilter = "filter" // nft priority keyword
)

type peerNFTState struct {
	txBps  int64
	rxBps  int64
	ips    []string
	active bool
}

type ifaceNFTState struct {
	ready bool // table + chains created
	peers map[string]*peerNFTState
}

// nftState tracks applied nft bandwidth limits.
type nftState struct {
	mu     sync.Mutex
	ifaces map[string]*ifaceNFTState
}

func newNFTState() *nftState {
	return &nftState{ifaces: make(map[string]*ifaceNFTState)}
}

func (s *nftState) iface(name string) *ifaceNFTState {
	st, ok := s.ifaces[name]
	if !ok {
		st = &ifaceNFTState{peers: make(map[string]*peerNFTState)}
		s.ifaces[name] = st
	}
	return st
}

// nftTableName returns a legal nft table name for the iface.
func nftTableName(iface string) string {
	return nftTablePref + sanitizeNFTIdent(iface)
}

// sanitizeNFTIdent keeps [A-Za-z0-9_], maps the rest to '_'.
func sanitizeNFTIdent(s string) string {
	if s == "" {
		return "iface"
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		return "iface"
	}
	// nft identifiers must not start with a digit.
	if unicode.IsDigit(rune(out[0])) {
		out = "n" + out
	}
	return out
}

func (s *nftState) sync(ctx context.Context, runner Runner, iface string, peers []DesiredPeer, full bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.iface(iface)

	desired := make(map[string]DesiredPeer, len(peers))
	for _, p := range peers {
		desired[p.PublicKey] = p
	}

	// Drop peers that are gone (full) or zeroed.
	for pub, prev := range st.peers {
		p, still := desired[pub]
		zero := still && p.BandwidthRxBps <= 0 && p.BandwidthTxBps <= 0
		missing := full && !still
		partialZero := !full && still && zero
		if (missing || zero || partialZero) && prev.active {
			delete(st.peers, pub)
		}
	}

	var errs []string
	for _, p := range peers {
		if p.BandwidthRxBps <= 0 && p.BandwidthTxBps <= 0 {
			// ensure removed from state on partial path
			if !full {
				delete(st.peers, p.PublicKey)
			}
			continue
		}
		ips := peerHostIPs(p)
		if len(ips) == 0 {
			errs = append(errs, fmt.Sprintf("peer %s: no host-sized assigned/allowed IPs for nft match", shortKey(p.PublicKey)))
			continue
		}
		prev := st.peers[p.PublicKey]
		if prev != nil && prev.active && prev.txBps == p.BandwidthTxBps && prev.rxBps == p.BandwidthRxBps && sameStrings(prev.ips, ips) {
			continue
		}
		st.peers[p.PublicKey] = &peerNFTState{
			txBps:  p.BandwidthTxBps,
			rxBps:  p.BandwidthRxBps,
			ips:    append([]string(nil), ips...),
			active: true,
		}
	}

	// Nothing limited → tear down table if we had one.
	if len(st.peers) == 0 {
		if st.ready {
			_ = nftDeleteTable(ctx, runner, iface)
			st.ready = false
		}
		if len(errs) > 0 {
			return fmt.Errorf("nft sync: %s", strings.Join(errs, "; "))
		}
		return nil
	}

	if err := nftEnsureTable(ctx, runner, iface, st); err != nil {
		return err
	}
	if err := nftRenderIface(ctx, runner, iface, st); err != nil {
		return err
	}
	if len(errs) > 0 {
		return fmt.Errorf("nft sync: %s", strings.Join(errs, "; "))
	}
	return nil
}

func nftEnsureTable(ctx context.Context, runner Runner, iface string, st *ifaceNFTState) error {
	if st.ready {
		return nil
	}
	table := nftTableName(iface)
	// Create table (ok if exists).
	if _, err := runner.Run(ctx, "nft", "add", "table", nftFamily, table); err != nil {
		if !nftExistsErr(err) {
			// try create via add after failed; continue only if list works
			if _, err2 := runner.Run(ctx, "nft", "list", "table", nftFamily, table); err2 != nil {
				return fmt.Errorf("nft add table %s: %w", table, err)
			}
		}
	}

	// Regular chains first (targets of jumps).
	for _, ch := range []string{nftChainRX, nftChainTX} {
		if _, err := runner.Run(ctx, "nft", "add", "chain", nftFamily, table, ch); err != nil && !nftExistsErr(err) {
			return fmt.Errorf("nft add chain %s: %w", ch, err)
		}
	}

	// Hook chains: early-return when not this iface, else jump to rx/tx.
	hooks := []struct {
		name  string
		hook  string
		match string // iifname | oifname
		jump  string
	}{
		{"rx_input", "input", "iifname", nftChainRX},
		{"rx_forward", "forward", "iifname", nftChainRX},
		{"tx_output", "output", "oifname", nftChainTX},
		{"tx_forward", "forward", "oifname", nftChainTX},
	}
	for _, h := range hooks {
		spec := fmt.Sprintf(
			`{ type filter hook %s priority %s; policy accept; }`,
			h.hook, nftPrioFilter,
		)
		if _, err := runner.Run(ctx, "nft", "add", "chain", nftFamily, table, h.name, spec); err != nil && !nftExistsErr(err) {
			return fmt.Errorf("nft add hook chain %s: %w", h.name, err)
		}
		// Idempotent enough: if rules already present from prior ready=false recovery, flush then re-add.
		_, _ = runner.Run(ctx, "nft", "flush", "chain", nftFamily, table, h.name)
		// return when packet is not on this iface
		if _, err := runner.Run(ctx, "nft", "add", "rule", nftFamily, table, h.name,
			h.match, "!=", iface, "return"); err != nil {
			return fmt.Errorf("nft hook %s return: %w", h.name, err)
		}
		if _, err := runner.Run(ctx, "nft", "add", "rule", nftFamily, table, h.name,
			"jump", h.jump); err != nil {
			return fmt.Errorf("nft hook %s jump: %w", h.name, err)
		}
	}
	st.ready = true
	return nil
}

func nftRenderIface(ctx context.Context, runner Runner, iface string, st *ifaceNFTState) error {
	table := nftTableName(iface)
	// Rebuild limit rules only (hook chains stay).
	for _, ch := range []string{nftChainRX, nftChainTX} {
		if _, err := runner.Run(ctx, "nft", "flush", "chain", nftFamily, table, ch); err != nil {
			return fmt.Errorf("nft flush %s: %w", ch, err)
		}
	}

	// Stable order by pubkey for deterministic tests/output.
	pubs := make([]string, 0, len(st.peers))
	for pub, p := range st.peers {
		if p != nil && p.active {
			pubs = append(pubs, pub)
		}
	}
	sort.Strings(pubs)

	var errs []string
	for _, pub := range pubs {
		p := st.peers[pub]
		cmt := nftComment(pub)
		for _, ip := range p.ips {
			v4 := strings.Contains(ip, ".") // host form; IPv6 uses ':'
			if strings.Contains(ip, ":") {
				v4 = false
			}
			if p.rxBps > 0 {
				rate, burst := formatNFTRate(p.rxBps)
				args := []string{"add", "rule", nftFamily, table, nftChainRX}
				if v4 {
					args = append(args, "ip", "saddr", ip)
				} else {
					args = append(args, "ip6", "saddr", ip)
				}
				args = append(args, "limit", "rate", "over", rate, "burst", burst, "drop", "comment", cmt)
				if _, err := runner.Run(ctx, "nft", args...); err != nil {
					errs = append(errs, fmt.Sprintf("rx %s %s: %v", shortKey(pub), ip, err))
				}
			}
			if p.txBps > 0 {
				rate, burst := formatNFTRate(p.txBps)
				args := []string{"add", "rule", nftFamily, table, nftChainTX}
				if v4 {
					args = append(args, "ip", "daddr", ip)
				} else {
					args = append(args, "ip6", "daddr", ip)
				}
				args = append(args, "limit", "rate", "over", rate, "burst", burst, "drop", "comment", cmt)
				if _, err := runner.Run(ctx, "nft", args...); err != nil {
					errs = append(errs, fmt.Sprintf("tx %s %s: %v", shortKey(pub), ip, err))
				}
			}
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("nft rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

func nftDeleteTable(ctx context.Context, runner Runner, iface string) error {
	table := nftTableName(iface)
	_, err := runner.Run(ctx, "nft", "delete", "table", nftFamily, table)
	if err != nil && !nftNotFoundErr(err) {
		return err
	}
	return nil
}

func nftExistsErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "File exists") ||
		strings.Contains(s, "already exists") ||
		strings.Contains(s, "exists")
}

func nftNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "No such file") ||
		strings.Contains(s, "does not exist") ||
		strings.Contains(s, "not found") ||
		strings.Contains(s, "No such")
}

// formatNFTRate converts bit/s to nft limit rate + burst strings.
// Returns e.g. ("125 kbytes/second", "3200 bytes").
func formatNFTRate(bps int64) (rate string, burst string) {
	if bps < 8 {
		bps = 8 // at least 1 byte/s
	}
	bytesPerSec := bps / 8
	if bytesPerSec < 1 {
		bytesPerSec = 1
	}

	switch {
	case bytesPerSec%1_000_000 == 0:
		rate = strconv.FormatInt(bytesPerSec/1_000_000, 10) + " mbytes/second"
	case bytesPerSec%1000 == 0:
		rate = strconv.FormatInt(bytesPerSec/1000, 10) + " kbytes/second"
	default:
		rate = strconv.FormatInt(bytesPerSec, 10) + " bytes/second"
	}

	// ~50ms of traffic, min ~2×MTU, max 16MiB — same policy as TC.
	b := bytesPerSec / 20
	if b < 3200 {
		b = 3200
	}
	if b > 16*1024*1024 {
		b = 16 * 1024 * 1024
	}
	switch {
	case b%1024 == 0 && b >= 1024:
		burst = strconv.FormatInt(b/1024, 10) + " kbytes"
	default:
		burst = strconv.FormatInt(b, 10) + " bytes"
	}
	return rate, burst
}

// nftComment builds a short rule comment from the peer public key.
func nftComment(pub string) string {
	// nft comment length is limited; keep it short and shell-safe.
	s := shortKey(pub)
	s = strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, s)
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

