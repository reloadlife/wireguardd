package wgbackend

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"sync"
)

// DNS backend names (config wireguard.dns_backend).
const (
	DNSBackendAuto       = "auto"
	DNSBackendResolvectl = "resolvectl"
	DNSBackendResolvconf = "resolvconf"
	DNSBackendNone       = "none"
)

// DNSConfig is the effective DNS policy for an interface.
type DNSConfig struct {
	Servers []string // IPv4/IPv6 nameservers
	Domains []string // search / routing domains (non-IP DNS= entries)
}

// ParseDNSList splits a mixed DNS= list (wg-quick style) into servers and domains.
// IP addresses (with optional %zone / port stripped for match) → servers;
// everything else → search domains.
func ParseDNSList(entries []string) DNSConfig {
	var cfg DNSConfig
	seenS, seenD := map[string]struct{}{}, map[string]struct{}{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		// strip optional port for detection: [2001:db8::1]:53 or 1.1.1.1:53
		host := e
		if strings.HasPrefix(host, "[") {
			if i := strings.LastIndex(host, "]"); i > 0 {
				host = host[1:i]
			}
		} else if h, _, err := net.SplitHostPort(e); err == nil {
			host = h
		}
		if ip := net.ParseIP(host); ip != nil {
			if _, ok := seenS[e]; !ok {
				seenS[e] = struct{}{}
				cfg.Servers = append(cfg.Servers, e)
			}
			continue
		}
		// domain-like
		d := strings.TrimPrefix(e, "~") // resolvectl routing domain marker
		if _, ok := seenD[d]; !ok {
			seenD[d] = struct{}{}
			cfg.Domains = append(cfg.Domains, d)
		}
	}
	return cfg
}

type ifaceDNSState struct {
	servers []string
	domains []string
	backend string // which backend last applied
	active  bool
}

type dnsState struct {
	mu     sync.Mutex
	ifaces map[string]*ifaceDNSState
}

func newDNSState() *dnsState {
	return &dnsState{ifaces: make(map[string]*ifaceDNSState)}
}

// SyncDNS applies or clears host DNS for the interface (wg-quick parity).
func (b *HostBackend) SyncDNS(ctx context.Context, desired DesiredInterface) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.dns == nil {
		b.dns = newDNSState()
	}
	backend := b.dnsBackend
	if backend == "" {
		backend = DNSBackendAuto
	}
	if backend == DNSBackendNone {
		return nil
	}
	return b.dns.sync(ctx, b.runner, backend, desired)
}

// clearInterfaceDNS reverts DNS for an interface (best-effort).
func (b *HostBackend) clearInterfaceDNS(ctx context.Context, name string) {
	if b.dns == nil || b.runner == nil {
		return
	}
	b.dns.mu.Lock()
	defer b.dns.mu.Unlock()
	st := b.dns.ifaces[name]
	if st == nil || !st.active {
		return
	}
	_ = clearDNS(ctx, b.runner, st.backend, name)
	delete(b.dns.ifaces, name)
}

func (s *dnsState) sync(ctx context.Context, runner Runner, backendPref string, desired DesiredInterface) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name := desired.Name
	st := s.ifaces[name]
	if st == nil {
		st = &ifaceDNSState{}
		s.ifaces[name] = st
	}

	cfg := ParseDNSList(desired.DNS)
	// Nothing to apply, or interface down → clear if we had state.
	if !desired.Enabled || (len(cfg.Servers) == 0 && len(cfg.Domains) == 0) {
		if st.active {
			_ = clearDNS(ctx, runner, st.backend, name)
			st.active = false
			st.servers, st.domains = nil, nil
		}
		return nil
	}

	backend := resolveDNSBackend(runner, backendPref)
	if backend == DNSBackendNone {
		return fmt.Errorf("dns: no resolvectl/resolvconf available (set wireguard.dns_backend or install one)")
	}

	// Skip if unchanged.
	if st.active && st.backend == backend && sameStrings(st.servers, cfg.Servers) && sameStrings(st.domains, cfg.Domains) {
		return nil
	}

	// Re-apply: clear old then set.
	if st.active {
		_ = clearDNS(ctx, runner, st.backend, name)
	}
	if err := applyDNS(ctx, runner, backend, name, cfg); err != nil {
		return err
	}
	st.servers = append([]string(nil), cfg.Servers...)
	st.domains = append([]string(nil), cfg.Domains...)
	st.backend = backend
	st.active = true
	return nil
}

func resolveDNSBackend(runner Runner, pref string) string {
	pref = strings.ToLower(strings.TrimSpace(pref))
	switch pref {
	case DNSBackendResolvectl, DNSBackendResolvconf, DNSBackendNone:
		return pref
	case "", DNSBackendAuto:
		// Prefer resolvectl (systemd-resolved), then resolvconf.
		if commandExists(runner, "resolvectl") {
			return DNSBackendResolvectl
		}
		if commandExists(runner, "resolvconf") {
			return DNSBackendResolvconf
		}
		// openresolv often ships as resolvconf
		return DNSBackendNone
	default:
		return DNSBackendNone
	}
}

func commandExists(runner Runner, name string) bool {
	// Prefer PATH lookup without invoking network.
	if _, err := exec.LookPath(name); err == nil {
		return true
	}
	// Fallback: try --help / -h via runner (tests inject LookPath via runner only)
	if runner != nil {
		if _, err := runner.Run(context.Background(), name, "--version"); err == nil {
			return true
		}
		// resolvconf may not support --version
		if _, err := runner.Run(context.Background(), "sh", "-c", "command -v "+name); err == nil {
			return true
		}
	}
	return false
}

func applyDNS(ctx context.Context, runner Runner, backend, iface string, cfg DNSConfig) error {
	switch backend {
	case DNSBackendResolvectl:
		return applyResolvectl(ctx, runner, iface, cfg)
	case DNSBackendResolvconf:
		return applyResolvconf(ctx, runner, iface, cfg)
	default:
		return fmt.Errorf("unknown dns backend %q", backend)
	}
}

func clearDNS(ctx context.Context, runner Runner, backend, iface string) error {
	switch backend {
	case DNSBackendResolvectl:
		// revert restores per-link DNS to unmanaged
		_, err := runner.Run(ctx, "resolvectl", "revert", iface)
		return err
	case DNSBackendResolvconf:
		// -f force delete
		_, err := runner.Run(ctx, "resolvconf", "-d", resolvconfIface(iface), "-f")
		if err != nil && strings.Contains(err.Error(), "No such") {
			return nil
		}
		return err
	default:
		return nil
	}
}

func applyResolvectl(ctx context.Context, runner Runner, iface string, cfg DNSConfig) error {
	if len(cfg.Servers) > 0 {
		args := append([]string{"dns", iface}, cfg.Servers...)
		if _, err := runner.Run(ctx, "resolvectl", args...); err != nil {
			return fmt.Errorf("resolvectl dns: %w", err)
		}
	}
	if len(cfg.Domains) > 0 {
		// Prefix ~ for routing domains when user didn't; keep bare for search.
		// wg-quick uses domains as both search and ~. for default-route cases.
		doms := make([]string, 0, len(cfg.Domains))
		for _, d := range cfg.Domains {
			doms = append(doms, d)
		}
		args := append([]string{"domain", iface}, doms...)
		if _, err := runner.Run(ctx, "resolvectl", args...); err != nil {
			return fmt.Errorf("resolvectl domain: %w", err)
		}
	}
	// Prefer this link for default DNS when servers are set (wg-quick-ish).
	if len(cfg.Servers) > 0 {
		_, _ = runner.Run(ctx, "resolvectl", "default-route", iface, "true")
		_, _ = runner.Run(ctx, "resolvectl", "llmnr", iface, "no")
	}
	return nil
}

func applyResolvconf(ctx context.Context, runner Runner, iface string, cfg DNSConfig) error {
	var b strings.Builder
	for _, s := range cfg.Servers {
		// resolvconf wants bare IPs in nameserver lines
		host := s
		if strings.HasPrefix(host, "[") {
			if i := strings.LastIndex(host, "]"); i > 0 {
				host = host[1:i]
			}
		} else if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		}
		fmt.Fprintf(&b, "nameserver %s\n", host)
	}
	if len(cfg.Domains) > 0 {
		fmt.Fprintf(&b, "search %s\n", strings.Join(cfg.Domains, " "))
	}
	content := b.String()
	if content == "" {
		return nil
	}
	// resolvconf -a tun.<iface> -m 0 -x  <<EOF
	name := resolvconfIface(iface)
	script := fmt.Sprintf("resolvconf -a %s -m 0 -x <<'WGDNS'\n%sWGDNS", name, content)
	_, err := runner.Run(ctx, "sh", "-c", script)
	if err != nil {
		return fmt.Errorf("resolvconf: %w", err)
	}
	return nil
}

// resolvconfIface matches wg-quick naming: tun.wg0 / tunnel.wg0 variants.
// openresolv and Debian resolvconf accept "tun.wg0".
func resolvconfIface(iface string) string {
	return "tun." + iface
}

// DetectDNSBackend returns the backend that would be used for "auto".
func DetectDNSBackend() string {
	if _, err := exec.LookPath("resolvectl"); err == nil {
		return DNSBackendResolvectl
	}
	if _, err := exec.LookPath("resolvconf"); err == nil {
		return DNSBackendResolvconf
	}
	return DNSBackendNone
}

// FormatDNSForConf rebuilds a DNS= line from servers+domains.
func FormatDNSForConf(cfg DNSConfig) []string {
	out := append([]string{}, cfg.Servers...)
	out = append(out, cfg.Domains...)
	sort.SliceStable(out, func(i, j int) bool {
		// keep servers first (already)
		return false
	})
	return out
}
