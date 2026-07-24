package wgbackend

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	// awgctrl-go is the AmneziaWG-aware fork of WireGuard/wgctrl-go: it speaks
	// both stock WireGuard and Amnezia netlink families, so Device()/handshake
	// sampling works for AWG twins (stock wgctrl silently missed them).
	wgctrl "github.com/advanced-wg/awgctrl-go"
	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

// HostBackend drives the real host via awgctrl + ip/wg/awg/tc/nft and userspace go.
type HostBackend struct {
	mu               sync.Mutex
	client           *wgctrl.Client
	runner           Runner
	confDir          string
	allowHooks       bool
	bandwidthBackend string
	dnsBackend       string
	tc               *tcState
	nft              *nftState
	routes           *routeState
	dns              *dnsState
	probe            *CapabilityProbe
	wgGoBin          string
	awgGoBin         string
	awgTool          string
	wgTool           string
}

// HostOptions configures HostBackend.
type HostOptions struct {
	ConfDir          string
	AllowHooks       bool
	BandwidthBackend string
	DNSBackend       string // auto | resolvectl | resolvconf | none
	Runner           Runner
	// Optional binary overrides (empty → PATH defaults).
	WireGuardGo string
	AmneziaWGGo string
	AWGTool     string
	WGTool      string
}

// NewHostBackend opens awgctrl (WireGuard + AmneziaWG netlink/userspace).
func NewHostBackend(opts HostOptions) (*HostBackend, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("awgctrl: %w", err)
	}
	r := opts.Runner
	if r == nil {
		r = ExecRunner{}
	}
	bw := opts.BandwidthBackend
	if bw == "" {
		bw = "tc"
	}
	dns := opts.DNSBackend
	if dns == "" {
		dns = DNSBackendAuto
	}
	wgGo := opts.WireGuardGo
	if wgGo == "" {
		wgGo = DefaultWireGuardGo
	}
	awgGo := opts.AmneziaWGGo
	if awgGo == "" {
		awgGo = DefaultAmneziaWGGo
	}
	awgTool := opts.AWGTool
	if awgTool == "" {
		awgTool = DefaultAWGTool
	}
	wgTool := opts.WGTool
	if wgTool == "" {
		wgTool = DefaultWGTool
	}
	return &HostBackend{
		client:           client,
		runner:           r,
		confDir:          opts.ConfDir,
		allowHooks:       opts.AllowHooks,
		tc:               newTCState(),
		nft:              newNFTState(),
		routes:           newRouteState(),
		dns:              newDNSState(),
		bandwidthBackend: bw,
		dnsBackend:       dns,
		probe:            NewCapabilityProbe(r, wgGo, awgGo, awgTool),
		wgGoBin:          wgGo,
		awgGoBin:         awgGo,
		awgTool:          awgTool,
		wgTool:           wgTool,
	}, nil
}

// Caps returns host backend capabilities (kernel / go / amnezia).
func (b *HostBackend) Caps(ctx context.Context) BackendCaps {
	if b.probe == nil {
		return BackendCaps{}
	}
	return b.probe.Caps(ctx)
}

// Close implements Backend.
func (b *HostBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.client.Close()
}

// Devices implements Backend.
//
// Primary path is awgctrl (stock WG + Amnezia netlink). CLI dump fills any
// links that netlink still misses (broken module, missing CAP_NET_ADMIN on
// the genl family, etc.) so AWG handshakes never go dark for billing.
func (b *HostBackend) Devices(ctx context.Context) ([]Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	byName := map[string]Device{}
	var ctrlErr error
	if devs, err := b.client.Devices(ctx); err == nil {
		for _, d := range devs {
			byName[d.Name] = b.enrichDevice(ctx, convertDevice(d))
		}
	} else {
		ctrlErr = err
	}
	// CLI fill: amnezia links not in byName, or any wg/awg name awgctrl missed.
	for _, name := range b.listWGLinkNames(ctx) {
		if _, ok := byName[name]; ok {
			continue
		}
		if dev, err := b.deviceFromCLI(ctx, name); err == nil {
			byName[name] = b.enrichDevice(ctx, *dev)
		}
	}
	if len(byName) == 0 && ctrlErr != nil {
		return nil, ctrlErr
	}
	out := make([]Device, 0, len(byName))
	for _, d := range byName {
		out = append(out, d)
	}
	return out, nil
}

// Device implements Backend.
//
// awgctrl speaks the Amnezia genl family, so peer handshakes/counters on AWG
// twins are visible to the sampler → control plane session_sync → $/hr+$/GB.
// CLI dump remains a last-resort fallback when netlink fails.
func (b *HostBackend) Device(ctx context.Context, name string) (*Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	d, err := b.client.Device(ctx, name)
	if err == nil {
		cd := b.enrichDevice(ctx, convertDevice(d))
		return &cd, nil
	}
	if dev, err2 := b.deviceFromCLI(ctx, name); err2 == nil {
		cd := b.enrichDevice(ctx, *dev)
		return &cd, nil
	}
	return nil, err
}

// listWGLinkNames returns host link names that look like wireguard/amneziawg.
func (b *HostBackend) listWGLinkNames(ctx context.Context) []string {
	out, err := b.runner.Run(ctx, "bash", "-c",
		`ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(wg|awg)' || true`)
	if err != nil {
		return nil
	}
	var names []string
	for _, n := range strings.Fields(out) {
		n = strings.TrimSpace(n)
		if n == "" || n == "mesh0" {
			continue
		}
		names = append(names, n)
	}
	return names
}

func convertDevice(d *wgtypes.Device) Device {
	priv := d.PrivateKey.String()
	if IsZeroKey(priv) {
		priv = ""
	}
	dev := Device{
		Name:         d.Name,
		PublicKey:    d.PublicKey.String(),
		PrivateKey:   priv,
		ListenPort:   d.ListenPort,
		FirewallMark: d.FirewallMark,
		Up:           true,
	}
	// awgctrl populates IsAmnezia from the Amnezia genl family.
	if d.IsAmnezia {
		dev.Protocol = ProtocolAWG
		dev.Backend = BackendAmneziaKernel
	} else {
		dev.Protocol = ProtocolWG
	}
	for _, p := range d.Peers {
		ep := ""
		if p.Endpoint != nil {
			ep = p.Endpoint.String()
		}
		allowed := make([]string, 0, len(p.AllowedIPs))
		for _, a := range p.AllowedIPs {
			allowed = append(allowed, a.String())
		}
		psk := p.PresharedKey.String()
		if IsZeroKey(psk) {
			psk = ""
		}
		dev.Peers = append(dev.Peers, Peer{
			PublicKey:                   p.PublicKey.String(),
			PresharedKey:                psk,
			Endpoint:                    ep,
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: p.PersistentKeepaliveInterval,
			LastHandshakeTime:           p.LastHandshakeTime,
			ReceiveBytes:                p.ReceiveBytes,
			TransmitBytes:               p.TransmitBytes,
		})
	}
	return dev
}

// enrichDevice adds link operstate, MTU, addresses, and backend detection from ip(8).
func (b *HostBackend) enrichDevice(ctx context.Context, dev Device) Device {
	if b.runner != nil {
		if addrs, err := b.listAddresses(ctx, dev.Name); err == nil {
			dev.Addresses = addrs
		}
		dev.Up = b.linkIsUp(ctx, dev.Name)
		if mtu := b.linkMTU(ctx, dev.Name); mtu > 0 {
			dev.MTU = mtu
		}
		dev.Backend = b.detectLiveBackend(ctx, dev.Name)
		if IsAmneziaBackend(dev.Backend) {
			dev.Protocol = ProtocolAWG
		} else {
			dev.Protocol = ProtocolWG
		}
	}
	return dev
}

// EnsureInterface implements Backend.
// Soft-apply: empty private key / empty address list leave host values untouched
// so adopting an existing interface never wipes keys or addresses.
func (b *HostBackend) EnsureInterface(ctx context.Context, desired DesiredInterface) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	proto := desired.Protocol
	if proto == "" {
		if IsAmneziaBackend(desired.Backend) || !desired.Amnezia.IsZero() {
			proto = ProtocolAWG
		} else {
			proto = ProtocolWG
		}
	}
	backend := desired.Backend
	if backend == "" {
		backend = BackendAuto
	}
	resolved, err := b.probe.ResolveBackend(ctx, proto, backend)
	if err != nil {
		return err
	}
	desired.ResolvedBackend = resolved

	if err := b.ensureLink(ctx, desired.Name, resolved); err != nil {
		return err
	}

	// Prefer awgctrl netlink (covers WG + AWG params). Fall back to awg/wg CLI
	// when the genl family is unavailable (older hosts / missing CAP).
	if err := b.configureDeviceAwgctrl(ctx, desired); err != nil {
		tool := b.toolForBackend(resolved)
		if err2 := b.configureDeviceViaCLI(ctx, tool, desired.Name, desired); err2 != nil {
			return fmt.Errorf("configure %s: awgctrl: %v; %s: %v", desired.Name, err, tool, err2)
		}
		if proto == ProtocolAWG || IsAmneziaBackend(resolved) {
			if err3 := b.setAmneziaParams(ctx, desired.Name, desired.Amnezia); err3 != nil {
				return fmt.Errorf("amnezia params via %s: %w", tool, err3)
			}
		}
	}

	if err := b.setMTU(ctx, desired.Name, desired.MTU); err != nil {
		return err
	}
	// Empty Addresses means "do not manage addresses" (adopt path).
	if len(desired.Addresses) > 0 {
		if err := b.syncAddresses(ctx, desired.Name, desired.Addresses); err != nil {
			return err
		}
	}
	if desired.Enabled {
		if err := b.setLinkUp(ctx, desired.Name, true); err != nil {
			return err
		}
	}
	return nil
}

func (b *HostBackend) configureDeviceAwgctrl(ctx context.Context, desired DesiredInterface) error {
	cfg := wgtypes.Config{ReplacePeers: false}
	if !IsZeroKey(desired.PrivateKey) {
		priv, err := wgtypes.ParseKey(desired.PrivateKey)
		if err != nil {
			return fmt.Errorf("private key: %w", err)
		}
		cfg.PrivateKey = &priv
	}
	if desired.ListenPort > 0 {
		p := desired.ListenPort
		cfg.ListenPort = &p
	}
	if desired.FwMark > 0 {
		f := desired.FwMark
		cfg.FirewallMark = &f
	}
	// Push Amnezia obfuscation over netlink when present (AWG twins).
	if !desired.Amnezia.IsZero() || desired.Protocol == ProtocolAWG || IsAmneziaBackend(desired.ResolvedBackend) {
		applyAmneziaToConfig(&cfg, desired.Amnezia)
	}
	hasAny := cfg.PrivateKey != nil || cfg.ListenPort != nil || cfg.FirewallMark != nil ||
		cfg.Jc != nil || cfg.Jmin != nil || cfg.Jmax != nil ||
		cfg.S1 != nil || cfg.S2 != nil || cfg.S3 != nil || cfg.S4 != nil ||
		cfg.H1 != nil || cfg.H2 != nil || cfg.H3 != nil || cfg.H4 != nil ||
		cfg.I1 != nil || cfg.I2 != nil || cfg.I3 != nil || cfg.I4 != nil || cfg.I5 != nil
	if !hasAny {
		return nil
	}
	if err := b.client.ConfigureDevice(ctx, desired.Name, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	return nil
}

// applyAmneziaToConfig copies product AmneziaParams into an awgctrl Config.
func applyAmneziaToConfig(cfg *wgtypes.Config, p AmneziaParams) {
	if p.IsZero() {
		// Neutral stock-compatible set so the iface is still marked AWG-capable.
		p = NeutralAmneziaParams()
	}
	intPtr := func(v int) *int {
		if v == 0 {
			return nil
		}
		x := v
		return &x
	}
	strPtr := func(s string) *string {
		if s == "" {
			return nil
		}
		x := s
		return &x
	}
	// Jc/Jmin/Jmax may legitimately be 0 (neutral) — still set when non-zero.
	if p.Jc != 0 {
		cfg.Jc = intPtr(p.Jc)
	}
	if p.Jmin != 0 {
		cfg.Jmin = intPtr(p.Jmin)
	}
	if p.Jmax != 0 {
		cfg.Jmax = intPtr(p.Jmax)
	}
	if p.S1 != 0 {
		cfg.S1 = intPtr(p.S1)
	}
	if p.S2 != 0 {
		cfg.S2 = intPtr(p.S2)
	}
	if p.S3 != 0 {
		cfg.S3 = intPtr(p.S3)
	}
	if p.S4 != 0 {
		cfg.S4 = intPtr(p.S4)
	}
	cfg.H1 = strPtr(p.H1)
	cfg.H2 = strPtr(p.H2)
	cfg.H3 = strPtr(p.H3)
	cfg.H4 = strPtr(p.H4)
	cfg.I1 = strPtr(p.I1)
	cfg.I2 = strPtr(p.I2)
	cfg.I3 = strPtr(p.I3)
	cfg.I4 = strPtr(p.I4)
	cfg.I5 = strPtr(p.I5)
	// H1-H4 empty after strPtr → force neutral headers so AWG peers can handshare.
	if cfg.H1 == nil && cfg.H2 == nil && cfg.H3 == nil && cfg.H4 == nil {
		n := NeutralAmneziaParams()
		cfg.H1, cfg.H2, cfg.H3, cfg.H4 = strPtr(n.H1), strPtr(n.H2), strPtr(n.H3), strPtr(n.H4)
	}
}

// RemoveInterface implements Backend.
func (b *HostBackend) RemoveInterface(ctx context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.clearInterfaceDNS(ctx, name)
	b.clearInterfaceTC(ctx, name)
	b.clearInterfaceRoutes(ctx, name)
	return b.deleteLinkExtended(ctx, name)
}

// SetUp implements Backend.
func (b *HostBackend) SetUp(ctx context.Context, name string, up bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.setLinkUp(ctx, name, up)
}

// ApplyPeers implements Backend.
// Diff-applies peers without ReplacePeers so kernel counters/handshakes are preserved.
func (b *HostBackend) ApplyPeers(ctx context.Context, iface string, peers []DesiredPeer) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	backend := b.detectLiveBackend(ctx, iface)
	if err := b.applyPeersAwgctrl(ctx, iface, peers, IsAmneziaBackend(backend)); err != nil {
		// Fall back to awg/wg CLI when netlink fails on amnezia devices.
		if IsAmneziaBackend(backend) || b.linkKind(ctx, iface) == "amneziawg" {
			tool := b.toolForBackend(backend)
			if err2 := b.applyPeersViaCLI(ctx, tool, iface, peers); err2 != nil {
				return fmt.Errorf("apply peers: awgctrl: %v; %s: %v", err, tool, err2)
			}
			return nil
		}
		return err
	}
	return nil
}

func (b *HostBackend) applyPeersAwgctrl(ctx context.Context, iface string, peers []DesiredPeer, amnezia bool) error {
	desired := make(map[string]DesiredPeer, len(peers))
	cfgs := make([]wgtypes.PeerConfig, 0, len(peers)+4)
	for _, p := range peers {
		desired[p.PublicKey] = p
		pub, err := wgtypes.ParseKey(p.PublicKey)
		if err != nil {
			return fmt.Errorf("peer public key: %w", err)
		}
		pc := wgtypes.PeerConfig{
			PublicKey:         pub,
			ReplaceAllowedIPs: true,
			// AWG peers must set AdvancedSecurity or the kernel treats them as
			// plain WG on an amnezia iface (handshake silence / no traffic).
			AdvancedSecurity: amnezia,
		}
		if p.PresharedKey != "" {
			psk, err := wgtypes.ParseKey(p.PresharedKey)
			if err != nil {
				return fmt.Errorf("peer psk: %w", err)
			}
			pc.PresharedKey = &psk
		}
		if p.Endpoint != "" {
			udp, err := net.ResolveUDPAddr("udp", p.Endpoint)
			if err != nil {
				return fmt.Errorf("endpoint %s: %w", p.Endpoint, err)
			}
			pc.Endpoint = udp
		}
		ka := time.Duration(p.PersistentKeepalive) * time.Second
		pc.PersistentKeepaliveInterval = &ka

		if !p.Suspended {
			for _, a := range p.AllowedIPs {
				ipnet, err := parseIPNet(a)
				if err != nil {
					return fmt.Errorf("allowed ip %s: %w", a, err)
				}
				pc.AllowedIPs = append(pc.AllowedIPs, *ipnet)
			}
		}
		cfgs = append(cfgs, pc)
	}

	// Remove peers no longer desired without wiping remaining peer state.
	if dev, err := b.client.Device(ctx, iface); err == nil {
		for _, lp := range dev.Peers {
			key := lp.PublicKey.String()
			if _, ok := desired[key]; !ok {
				cfgs = append(cfgs, wgtypes.PeerConfig{
					PublicKey: lp.PublicKey,
					Remove:    true,
				})
			}
		}
	}

	cfg := wgtypes.Config{
		ReplacePeers: false,
		Peers:        cfgs,
	}
	if err := b.client.ConfigureDevice(ctx, iface, cfg); err != nil {
		return fmt.Errorf("apply peers: %w", err)
	}
	return nil
}

func parseIPNet(a string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(a)
	if err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(a)
	if ip == nil {
		return nil, err
	}
	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// ApplySuspendRoutes implements Backend.
func (b *HostBackend) ApplySuspendRoutes(ctx context.Context, iface string, peer DesiredPeer, suspend bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	_ = iface
	return b.applySuspendRoutes(ctx, peer, suspend)
}

// ExportConf implements Backend.
func (b *HostBackend) ExportConf(ctx context.Context, path string, content string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RunHook implements Backend.
func (b *HostBackend) RunHook(ctx context.Context, hook string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if !b.allowHooks || hook == "" {
		return nil
	}
	_, err := b.runner.Run(ctx, "sh", "-c", hook)
	return err
}
