package wgbackend

import (
	"context"
	"fmt"
	"hash/fnv"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// TC handle layout (per WireGuard iface):
//
//	Egress root HTB ........ 1:
//	  default class ........ 1:1   (unlimited catch-all)
//	  per-peer TX class .... 1:<minor>  minor in [0x10, 0xffe]
//	Ingress qdisc .......... ffff:
//	  per-peer police ...... match src IP (v4/v6)
//
// TX  = traffic from this host → peer tunnel IP  (dst match, HTB)
// RX  = traffic from peer → this host            (src match, ingress police)

const (
	tcRootHandle    = "1:"
	tcDefaultClass  = "1:1"
	tcDefaultMinor  = 1
	tcIngressParent = "ffff:"
	tcMinorMin      = 0x10
	tcMinorMax      = 0xffe
)

type peerTCState struct {
	minor  uint32
	txBps  int64
	rxBps  int64
	ips    []string // host addresses used for filters
	active bool
}

// tcState tracks applied bandwidth limits so we can update/remove cleanly.
type tcState struct {
	mu     sync.Mutex
	ifaces map[string]*ifaceTCState // iface name
}

type ifaceTCState struct {
	rootReady    bool
	ingressReady bool
	// minor -> pubkey (collision tracking)
	minors map[uint32]string
	peers  map[string]*peerTCState // pubkey
}

func newTCState() *tcState {
	return &tcState{ifaces: make(map[string]*ifaceTCState)}
}

func (s *tcState) iface(name string) *ifaceTCState {
	st, ok := s.ifaces[name]
	if !ok {
		st = &ifaceTCState{
			minors: make(map[uint32]string),
			peers:  make(map[string]*peerTCState),
		}
		s.ifaces[name] = st
	}
	return st
}

// SyncBandwidth applies full per-peer bandwidth limits for an interface and removes stale peers.
// peers must be the complete desired set for the interface.
// Supported backends: tc | nft | none.
func (b *HostBackend) SyncBandwidth(ctx context.Context, iface string, peers []DesiredPeer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.bandwidthBackend {
	case "none", "":
		return nil
	case "tc":
		if b.tc == nil {
			b.tc = newTCState()
		}
		// Drop leftover nft table if operator switched backends.
		b.clearInterfaceNFT(ctx, iface)
		return b.tc.sync(ctx, b.runner, iface, peers, true)
	case "nft":
		if b.nft == nil {
			b.nft = newNFTState()
		}
		// Drop leftover tc qdiscs if operator switched backends.
		b.clearInterfaceTCOnly(ctx, iface)
		return b.nft.sync(ctx, b.runner, iface, peers, true)
	default:
		return fmt.Errorf("unsupported bandwidth_backend %q (supported: tc, nft, none)", b.bandwidthBackend)
	}
}

// ApplyBandwidth updates a single peer's limits without removing other peers' state.
func (b *HostBackend) ApplyBandwidth(ctx context.Context, iface string, peer DesiredPeer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	switch b.bandwidthBackend {
	case "none", "":
		return nil
	case "tc":
		if b.tc == nil {
			b.tc = newTCState()
		}
		return b.tc.sync(ctx, b.runner, iface, []DesiredPeer{peer}, false)
	case "nft":
		if b.nft == nil {
			b.nft = newNFTState()
		}
		return b.nft.sync(ctx, b.runner, iface, []DesiredPeer{peer}, false)
	default:
		return fmt.Errorf("unsupported bandwidth_backend %q (supported: tc, nft, none)", b.bandwidthBackend)
	}
}

// clearInterfaceTC removes bandwidth enforcement for an interface (tc and/or nft).
func (b *HostBackend) clearInterfaceTC(ctx context.Context, iface string) {
	b.clearInterfaceTCOnly(ctx, iface)
	b.clearInterfaceNFT(ctx, iface)
}

// clearInterfaceTCOnly removes Linux tc qdiscs for the iface (best-effort).
func (b *HostBackend) clearInterfaceTCOnly(ctx context.Context, iface string) {
	if b.runner != nil {
		_, _ = b.runner.Run(ctx, "tc", "qdisc", "del", "dev", iface, "root")
		_, _ = b.runner.Run(ctx, "tc", "qdisc", "del", "dev", iface, "ingress")
	}
	if b.tc != nil {
		b.tc.mu.Lock()
		delete(b.tc.ifaces, iface)
		b.tc.mu.Unlock()
	}
}

// clearInterfaceNFT removes the per-iface nftables table (best-effort).
func (b *HostBackend) clearInterfaceNFT(ctx context.Context, iface string) {
	if b.runner != nil {
		_ = nftDeleteTable(ctx, b.runner, iface)
	}
	if b.nft != nil {
		b.nft.mu.Lock()
		delete(b.nft.ifaces, iface)
		b.nft.mu.Unlock()
	}
}

func (s *tcState) sync(ctx context.Context, runner Runner, iface string, peers []DesiredPeer, full bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.iface(iface)

	desired := make(map[string]DesiredPeer, len(peers))
	for _, p := range peers {
		desired[p.PublicKey] = p
	}

	// Remove peers no longer present (full sync only) or with zero limits.
	for pub, prev := range st.peers {
		p, still := desired[pub]
		zero := still && p.BandwidthRxBps <= 0 && p.BandwidthTxBps <= 0
		missing := full && !still
		// partial update: only clear this peer when it appears with zero limits
		partialZero := !full && still && zero
		needClear := (missing || zero || partialZero) && prev.active
		if needClear {
			if err := clearPeerTC(ctx, runner, iface, prev); err != nil {
				return fmt.Errorf("clear peer %s: %w", shortKey(pub), err)
			}
			delete(st.minors, prev.minor)
			delete(st.peers, pub)
		}
	}

	// Nothing limited → leave root in place (harmless) or tear down if no peers left with limits.
	anyLimit := false
	for _, p := range peers {
		if p.BandwidthRxBps > 0 || p.BandwidthTxBps > 0 {
			anyLimit = true
			break
		}
	}
	if !anyLimit {
		return nil
	}

	if err := ensureRootHTB(ctx, runner, iface, st); err != nil {
		return err
	}
	if err := ensureIngress(ctx, runner, iface, st); err != nil {
		return err
	}

	var errs []string
	for _, p := range peers {
		if p.BandwidthRxBps <= 0 && p.BandwidthTxBps <= 0 {
			continue
		}
		ips := peerHostIPs(p)
		if len(ips) == 0 {
			errs = append(errs, fmt.Sprintf("peer %s: no host-sized assigned/allowed IPs for TC match", shortKey(p.PublicKey)))
			continue
		}
		prev := st.peers[p.PublicKey]
		// Skip if unchanged.
		if prev != nil && prev.active && prev.txBps == p.BandwidthTxBps && prev.rxBps == p.BandwidthRxBps && sameStrings(prev.ips, ips) {
			continue
		}
		// Re-apply: clear old then set new.
		if prev != nil && prev.active {
			_ = clearPeerTC(ctx, runner, iface, prev)
			delete(st.minors, prev.minor)
		}
		minor := allocateMinor(st, p.PublicKey)
		state := &peerTCState{
			minor:  minor,
			txBps:  p.BandwidthTxBps,
			rxBps:  p.BandwidthRxBps,
			ips:    append([]string(nil), ips...),
			active: true,
		}
		if err := applyPeerTC(ctx, runner, iface, p, state); err != nil {
			errs = append(errs, fmt.Sprintf("peer %s: %v", shortKey(p.PublicKey), err))
			// best-effort cleanup partial
			_ = clearPeerTC(ctx, runner, iface, state)
			delete(st.minors, minor)
			continue
		}
		st.peers[p.PublicKey] = state
		st.minors[minor] = p.PublicKey
	}
	if len(errs) > 0 {
		return fmt.Errorf("tc sync: %s", strings.Join(errs, "; "))
	}
	return nil
}

func ensureRootHTB(ctx context.Context, runner Runner, iface string, st *ifaceTCState) error {
	if st.rootReady {
		// still replace default class rates in case first add failed partially
		_, _ = runner.Run(ctx, "tc", "class", "replace", "dev", iface, "parent", tcRootHandle,
			"classid", tcDefaultClass, "htb", "rate", "100gbit", "ceil", "100gbit")
		return nil
	}
	// Try add root; if exists, replace is fine via del+add only when needed.
	_, err := runner.Run(ctx, "tc", "qdisc", "add", "dev", iface, "root", "handle", tcRootHandle, "htb", "default", strconv.Itoa(tcDefaultMinor))
	if err != nil {
		// Already present — treat as ok if show works
		if !strings.Contains(err.Error(), "File exists") && !strings.Contains(err.Error(), "Exclusivity flag") {
			// try replace root
			_, err2 := runner.Run(ctx, "tc", "qdisc", "replace", "dev", iface, "root", "handle", tcRootHandle, "htb", "default", strconv.Itoa(tcDefaultMinor))
			if err2 != nil {
				return fmt.Errorf("tc root htb: %w (also: %v)", err, err2)
			}
		}
	}
	// Unlimited default class for non-classified traffic
	_, err = runner.Run(ctx, "tc", "class", "replace", "dev", iface, "parent", tcRootHandle,
		"classid", tcDefaultClass, "htb", "rate", "100gbit", "ceil", "100gbit")
	if err != nil {
		return fmt.Errorf("tc default class: %w", err)
	}
	st.rootReady = true
	return nil
}

func ensureIngress(ctx context.Context, runner Runner, iface string, st *ifaceTCState) error {
	if st.ingressReady {
		return nil
	}
	_, err := runner.Run(ctx, "tc", "qdisc", "add", "dev", iface, "handle", tcIngressParent, "ingress")
	if err != nil {
		if !strings.Contains(err.Error(), "File exists") && !strings.Contains(err.Error(), "Exclusivity") {
			// replace path
			_, err2 := runner.Run(ctx, "tc", "qdisc", "replace", "dev", iface, "handle", tcIngressParent, "ingress")
			if err2 != nil && !strings.Contains(err2.Error(), "File exists") {
				return fmt.Errorf("tc ingress: %w", err)
			}
		}
	}
	st.ingressReady = true
	return nil
}

func applyPeerTC(ctx context.Context, runner Runner, iface string, peer DesiredPeer, st *peerTCState) error {
	classID := fmt.Sprintf("1:%x", st.minor)
	pref := int(st.minor) // unique prio/pref for filters

	// --- TX (egress HTB) ---
	if st.txBps > 0 {
		rate := formatTCRate(st.txBps)
		burst := formatTCBurst(st.txBps)
		_, err := runner.Run(ctx, "tc", "class", "replace", "dev", iface,
			"parent", tcRootHandle, "classid", classID,
			"htb", "rate", rate, "ceil", rate, "burst", burst, "cburst", burst)
		if err != nil {
			return fmt.Errorf("tx class: %w", err)
		}
		// Optional SFQ under class for fairness among peer flows
		_, _ = runner.Run(ctx, "tc", "qdisc", "replace", "dev", iface,
			"parent", classID, "handle", fmt.Sprintf("%x:", st.minor), "sfq", "perturb", "10")

		for _, ip := range st.ips {
			if err := addEgressFilter(ctx, runner, iface, ip, classID, pref); err != nil {
				return fmt.Errorf("tx filter %s: %w", ip, err)
			}
			pref++
		}
	}

	// --- RX (ingress police) ---
	if st.rxBps > 0 {
		rate := formatTCRate(st.rxBps)
		burst := formatTCBurst(st.rxBps)
		for _, ip := range st.ips {
			if err := addIngressPolice(ctx, runner, iface, ip, rate, burst, pref); err != nil {
				return fmt.Errorf("rx police %s: %w", ip, err)
			}
			pref++
		}
	}
	return nil
}

func clearPeerTC(ctx context.Context, runner Runner, iface string, st *peerTCState) error {
	if st == nil {
		return nil
	}
	classID := fmt.Sprintf("1:%x", st.minor)
	// Delete filters by scanning is hard; delete by pref range we used (minor .. minor+N)
	// Prefer deleting class (drops child qdisc) and ingress filters matching our IPs.
	for i := 0; i < len(st.ips)*2+8; i++ {
		pref := strconv.Itoa(int(st.minor) + i)
		_, _ = runner.Run(ctx, "tc", "filter", "del", "dev", iface, "parent", tcRootHandle, "pref", pref)
		_, _ = runner.Run(ctx, "tc", "filter", "del", "dev", iface, "parent", tcIngressParent, "pref", pref)
	}
	// Also try protocol-specific deletes for flower/u32 leftovers
	for _, ip := range st.ips {
		_ = ip
	}
	_, _ = runner.Run(ctx, "tc", "qdisc", "del", "dev", iface, "parent", classID)
	_, _ = runner.Run(ctx, "tc", "class", "del", "dev", iface, "classid", classID)
	st.active = false
	return nil
}

func addEgressFilter(ctx context.Context, runner Runner, iface, ip, classID string, pref int) error {
	proto, matchArgs, err := matchDst(ip)
	if err != nil {
		return err
	}
	args := []string{
		"filter", "replace", "dev", iface,
		"protocol", proto, "parent", tcRootHandle,
		"prio", strconv.Itoa(pref),
	}
	args = append(args, matchArgs...)
	args = append(args, "flowid", classID)
	_, err = runner.Run(ctx, "tc", args...)
	return err
}

func addIngressPolice(ctx context.Context, runner Runner, iface, ip, rate, burst string, pref int) error {
	proto, matchArgs, err := matchSrc(ip)
	if err != nil {
		return err
	}
	args := []string{
		"filter", "replace", "dev", iface,
		"protocol", proto, "parent", tcIngressParent,
		"prio", strconv.Itoa(pref),
	}
	args = append(args, matchArgs...)
	// police rate <rate> burst <burst> drop
	args = append(args, "action", "police", "rate", rate, "burst", burst, "drop")
	_, err = runner.Run(ctx, "tc", args...)
	return err
}

// matchDst builds u32 match for destination IP (egress to peer).
func matchDst(ip string) (proto string, args []string, err error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", nil, fmt.Errorf("invalid ip %q", ip)
	}
	if v4 := parsed.To4(); v4 != nil {
		return "ip", []string{"u32", "match", "ip", "dst", v4.String() + "/32"}, nil
	}
	// ipv6
	return "ipv6", []string{"u32", "match", "ip6", "dst", parsed.String() + "/128"}, nil
}

// matchSrc builds u32 match for source IP (ingress from peer).
func matchSrc(ip string) (proto string, args []string, err error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", nil, fmt.Errorf("invalid ip %q", ip)
	}
	if v4 := parsed.To4(); v4 != nil {
		return "ip", []string{"u32", "match", "ip", "src", v4.String() + "/32"}, nil
	}
	return "ipv6", []string{"u32", "match", "ip6", "src", parsed.String() + "/128"}, nil
}

// peerHostIPs returns /32 or /128 addresses used for TC matching.
func peerHostIPs(p DesiredPeer) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			return
		}
		host := raw
		if strings.Contains(raw, "/") {
			ip, ipnet, err := net.ParseCIDR(raw)
			if err != nil {
				return
			}
			ones, bits := ipnet.Mask.Size()
			// only host routes
			if ones != bits {
				return
			}
			host = ip.String()
		} else {
			if net.ParseIP(raw) == nil {
				return
			}
		}
		if _, ok := seen[host]; ok {
			return
		}
		seen[host] = struct{}{}
		out = append(out, host)
	}
	for _, a := range p.AssignedIPs {
		add(a)
	}
	if len(out) == 0 {
		for _, a := range p.AllowedIPs {
			add(a)
		}
	}
	sort.Strings(out)
	return out
}

func allocateMinor(st *ifaceTCState, pubkey string) uint32 {
	base := peerMinorHint(pubkey)
	for i := uint32(0); i < (tcMinorMax - tcMinorMin + 1); i++ {
		m := tcMinorMin + (base+i)%(tcMinorMax-tcMinorMin+1)
		if m == tcDefaultMinor {
			continue
		}
		if owner, ok := st.minors[m]; !ok || owner == pubkey {
			return m
		}
	}
	// fallback — should be unreachable with 4k slots
	return tcMinorMin + peerMinorHint(pubkey)%100
}

func peerMinorHint(pubkey string) uint32 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(pubkey))
	return h.Sum32()
}

// formatTCRate formats bits/sec for tc (prefers kbit/mbit when aligned).
func formatTCRate(bps int64) string {
	if bps < 1 {
		bps = 1
	}
	if bps%1_000_000 == 0 {
		return strconv.FormatInt(bps/1_000_000, 10) + "mbit"
	}
	if bps%1000 == 0 {
		return strconv.FormatInt(bps/1000, 10) + "kbit"
	}
	return strconv.FormatInt(bps, 10) + "bit"
}

// formatTCBurst returns a reasonable HTB/police burst (bytes).
// ~50ms of traffic, minimum 2×MTU-ish (3200), maximum 16MiB.
func formatTCBurst(bps int64) string {
	burst := bps / 8 / 20 // 50ms in bytes
	if burst < 3200 {
		burst = 3200
	}
	if burst > 16*1024*1024 {
		burst = 16 * 1024 * 1024
	}
	return strconv.FormatInt(burst, 10)
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func shortKey(pub string) string {
	if len(pub) <= 12 {
		return pub
	}
	return pub[:8] + "…"
}
