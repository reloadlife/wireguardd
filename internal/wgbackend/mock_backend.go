package wgbackend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// MockBackend is an in-memory backend for tests.
type MockBackend struct {
	mu       sync.Mutex
	DevicesM map[string]*Device
	Hooks    []string
	Exports  map[string]string
	// FailNext if set causes the next mutating call to fail.
	FailNext error
}

// NewMock creates an empty mock backend.
func NewMock() *MockBackend {
	return &MockBackend{
		DevicesM: make(map[string]*Device),
		Exports:  make(map[string]string),
	}
}

func (m *MockBackend) fail() error {
	if m.FailNext != nil {
		err := m.FailNext
		m.FailNext = nil
		return err
	}
	return nil
}

// Devices implements Backend.
func (m *MockBackend) Devices(ctx context.Context) ([]Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Device, 0, len(m.DevicesM))
	for _, d := range m.DevicesM {
		cp := *d
		cp.Peers = append([]Peer(nil), d.Peers...)
		out = append(out, cp)
	}
	return out, nil
}

// Device implements Backend.
func (m *MockBackend) Device(ctx context.Context, name string) (*Device, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.DevicesM[name]
	if !ok {
		return nil, fmt.Errorf("device %s not found", name)
	}
	cp := *d
	cp.Peers = append([]Peer(nil), d.Peers...)
	return &cp, nil
}

// EnsureInterface implements Backend.
func (m *MockBackend) EnsureInterface(ctx context.Context, desired DesiredInterface) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	d, ok := m.DevicesM[desired.Name]
	if !ok {
		d = &Device{Name: desired.Name}
		m.DevicesM[desired.Name] = d
	}
	d.PrivateKey = desired.PrivateKey
	d.ListenPort = desired.ListenPort
	d.FirewallMark = desired.FwMark
	d.Up = desired.Enabled
	return nil
}

// RemoveInterface implements Backend.
func (m *MockBackend) RemoveInterface(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	delete(m.DevicesM, name)
	return nil
}

// SetUp implements Backend.
func (m *MockBackend) SetUp(ctx context.Context, name string, up bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	d, ok := m.DevicesM[name]
	if !ok {
		return fmt.Errorf("device %s not found", name)
	}
	d.Up = up
	return nil
}

// ApplyPeers implements Backend.
func (m *MockBackend) ApplyPeers(ctx context.Context, iface string, peers []DesiredPeer) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail(); err != nil {
		return err
	}
	d, ok := m.DevicesM[iface]
	if !ok {
		return fmt.Errorf("device %s not found", iface)
	}
	// Preserve counters/handshake across reapply (mirrors host kernel behaviour).
	prev := make(map[string]Peer, len(d.Peers))
	for _, p := range d.Peers {
		prev[p.PublicKey] = p
	}
	out := make([]Peer, 0, len(peers))
	for _, p := range peers {
		allowed := p.AllowedIPs
		if p.Suspended {
			allowed = nil
		}
		np := Peer{
			PublicKey:    p.PublicKey,
			PresharedKey: p.PresharedKey,
			Endpoint:     p.Endpoint,
			AllowedIPs:   append([]string(nil), allowed...),
		}
		if old, ok := prev[p.PublicKey]; ok {
			np.ReceiveBytes = old.ReceiveBytes
			np.TransmitBytes = old.TransmitBytes
			np.LastHandshakeTime = old.LastHandshakeTime
			if np.Endpoint == "" {
				np.Endpoint = old.Endpoint
			}
		}
		out = append(out, np)
	}
	d.Peers = out
	return nil
}

// ApplySuspendRoutes implements Backend.
func (m *MockBackend) ApplySuspendRoutes(ctx context.Context, iface string, peer DesiredPeer, suspend bool) error {
	return nil
}

// ApplyBandwidth implements Backend.
func (m *MockBackend) ApplyBandwidth(ctx context.Context, iface string, peer DesiredPeer) error {
	return nil
}

// ExportConf implements Backend.
func (m *MockBackend) ExportConf(ctx context.Context, path string, content string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Exports[path] = content
	if dir := filepath.Dir(path); dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	return os.WriteFile(path, []byte(content), 0o600)
}

// RunHook implements Backend.
func (m *MockBackend) RunHook(ctx context.Context, hook string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Hooks = append(m.Hooks, hook)
	return nil
}

// Close implements Backend.
func (m *MockBackend) Close() error { return nil }

// SetPeerTraffic sets mock transfer counters for tests.
func (m *MockBackend) SetPeerTraffic(iface, pubkey string, rx, tx int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, ok := m.DevicesM[iface]
	if !ok {
		return
	}
	for i := range d.Peers {
		if d.Peers[i].PublicKey == pubkey {
			d.Peers[i].ReceiveBytes = rx
			d.Peers[i].TransmitBytes = tx
			return
		}
	}
}
