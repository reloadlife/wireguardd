package wgbackend

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// HostBackend drives the real host via wgctrl + ip/wg/tc.
type HostBackend struct {
	mu               sync.Mutex
	client           *wgctrl.Client
	runner           Runner
	confDir          string
	allowHooks       bool
	bandwidthBackend string
	dnsBackend       string
	tc               *tcState
	routes           *routeState
	dns              *dnsState
}

// HostOptions configures HostBackend.
type HostOptions struct {
	ConfDir          string
	AllowHooks       bool
	BandwidthBackend string
	DNSBackend       string // auto | resolvectl | resolvconf | none
	Runner           Runner
}

// NewHostBackend opens wgctrl.
func NewHostBackend(opts HostOptions) (*HostBackend, error) {
	client, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("wgctrl: %w", err)
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
	return &HostBackend{
		client:           client,
		runner:           r,
		confDir:          opts.ConfDir,
		allowHooks:       opts.AllowHooks,
		tc:               newTCState(),
		routes:           newRouteState(),
		dns:              newDNSState(),
		bandwidthBackend: bw,
		dnsBackend:       dns,
	}, nil
}

// Close implements Backend.
func (b *HostBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.client.Close()
}

// Devices implements Backend.
func (b *HostBackend) Devices(ctx context.Context) ([]Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	devs, err := b.client.Devices()
	if err != nil {
		return nil, err
	}
	out := make([]Device, 0, len(devs))
	for _, d := range devs {
		out = append(out, convertDevice(d))
	}
	return out, nil
}

// Device implements Backend.
func (b *HostBackend) Device(ctx context.Context, name string) (*Device, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	d, err := b.client.Device(name)
	if err != nil {
		return nil, err
	}
	cd := convertDevice(d)
	return &cd, nil
}

func convertDevice(d *wgtypes.Device) Device {
	dev := Device{
		Name:         d.Name,
		PublicKey:    d.PublicKey.String(),
		PrivateKey:   d.PrivateKey.String(),
		ListenPort:   d.ListenPort,
		FirewallMark: d.FirewallMark,
		Up:           true, // presence implies configured; link state via ip if needed
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
		dev.Peers = append(dev.Peers, Peer{
			PublicKey:                   p.PublicKey.String(),
			PresharedKey:                p.PresharedKey.String(),
			Endpoint:                    ep,
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: p.PersistentKeepaliveInterval,
			LastHandshakeTime:           p.LastHandshakeTime,
			ReceiveBytes:                p.ReceiveBytes,
			TransmitBytes:               p.TransmitBytes,
		})
	}
	// refine Up from ip link
	return dev
}

// EnsureInterface implements Backend.
func (b *HostBackend) EnsureInterface(ctx context.Context, desired DesiredInterface) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.createLink(ctx, desired.Name); err != nil {
		return err
	}
	priv, err := wgtypes.ParseKey(desired.PrivateKey)
	if err != nil {
		return fmt.Errorf("private key: %w", err)
	}
	cfg := wgtypes.Config{
		PrivateKey:   &priv,
		ReplacePeers: false,
	}
	if desired.ListenPort > 0 {
		p := desired.ListenPort
		cfg.ListenPort = &p
	}
	if desired.FwMark > 0 {
		f := desired.FwMark
		cfg.FirewallMark = &f
	}
	if err := b.client.ConfigureDevice(desired.Name, cfg); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	if err := b.setMTU(ctx, desired.Name, desired.MTU); err != nil {
		return err
	}
	if err := b.syncAddresses(ctx, desired.Name, desired.Addresses); err != nil {
		return err
	}
	if desired.Enabled {
		if err := b.setLinkUp(ctx, desired.Name, true); err != nil {
			return err
		}
	}
	return nil
}

// RemoveInterface implements Backend.
func (b *HostBackend) RemoveInterface(ctx context.Context, name string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.clearInterfaceDNS(ctx, name)
	b.clearInterfaceTC(ctx, name)
	b.clearInterfaceRoutes(ctx, name)
	return b.deleteLink(ctx, name)
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
	if dev, err := b.client.Device(iface); err == nil {
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
	if err := b.client.ConfigureDevice(iface, cfg); err != nil {
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
