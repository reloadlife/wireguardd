package wgbackend

import (
	"context"
	"net"
	"time"
)

// Device is live WireGuard device state.
type Device struct {
	Name         string
	PublicKey    string
	PrivateKey   string
	ListenPort   int
	FirewallMark int
	Peers        []Peer
	Up           bool
}

// Peer is live peer state.
type Peer struct {
	PublicKey                   string
	PresharedKey                string
	Endpoint                    string
	AllowedIPs                  []string
	PersistentKeepaliveInterval time.Duration
	LastHandshakeTime           time.Time
	ReceiveBytes                int64
	TransmitBytes               int64
}

// DesiredInterface is the desired interface configuration to apply.
type DesiredInterface struct {
	Name       string
	PrivateKey string
	ListenPort int
	FwMark     int
	MTU        int
	Addresses  []string
	TableMode  string
	TableID    *int
	DNS        []string
	PreUp      string
	PostUp     string
	PreDown    string
	PostDown   string
	Enabled    bool
	Peers      []DesiredPeer
}

// DesiredPeer is desired peer configuration.
type DesiredPeer struct {
	PublicKey           string
	PresharedKey        string
	Endpoint            string
	AllowedIPs          []string
	AssignedIPs         []string
	PersistentKeepalive int
	Suspended           bool
	BandwidthRxBps      int64
	BandwidthTxBps      int64
}

// Backend applies and observes WireGuard state on the host.
type Backend interface {
	// Devices returns live devices.
	Devices(ctx context.Context) ([]Device, error)
	// Device returns one live device by name.
	Device(ctx context.Context, name string) (*Device, error)
	// EnsureInterface creates/configures the WireGuard device and addresses.
	EnsureInterface(ctx context.Context, desired DesiredInterface) error
	// RemoveInterface tears down a device.
	RemoveInterface(ctx context.Context, name string) error
	// SetUp brings the link up or down.
	SetUp(ctx context.Context, name string, up bool) error
	// ApplyPeers replaces peer config for a device.
	ApplyPeers(ctx context.Context, iface string, peers []DesiredPeer) error
	// SuspendPeerApplies blackhole/null policy for a peer's IPs.
	ApplySuspendRoutes(ctx context.Context, iface string, peer DesiredPeer, suspend bool) error
	// ApplyBandwidth applies per-peer bandwidth limits (single peer).
	ApplyBandwidth(ctx context.Context, iface string, peer DesiredPeer) error
	// SyncBandwidth applies/removes full per-peer bandwidth policy for an interface.
	// Implementations that only support single-peer ApplyBandwidth may loop peers.
	SyncBandwidth(ctx context.Context, iface string, peers []DesiredPeer) error
	// SyncRoutes installs AllowedIP routes + policy rules per Table= (wg-quick).
	SyncRoutes(ctx context.Context, desired DesiredInterface) error
	// SyncDNS applies host DNS for the interface (resolvectl / resolvconf).
	SyncDNS(ctx context.Context, desired DesiredInterface) error
	// ExportConf writes a conf file (wg-quick style) for the interface.
	ExportConf(ctx context.Context, path string, content string) error
	// RunHooks runs pre/post up/down if allowed.
	RunHook(ctx context.Context, hook string) error
	// Close releases resources.
	Close() error
}

// ParseEndpoint parses host:port endpoint.
func ParseEndpoint(endpoint string) (*net.UDPAddr, error) {
	if endpoint == "" {
		return nil, nil
	}
	return net.ResolveUDPAddr("udp", endpoint)
}
