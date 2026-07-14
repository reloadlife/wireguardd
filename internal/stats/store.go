package stats

import (
	"sync"
	"time"
)

// Cache holds the latest rates and counters for metrics/SNMP/API.
type Cache struct {
	mu     sync.RWMutex
	ifaces map[string]*IfaceStats
	peers  map[string]*PeerStats // key: iface/pubkey
}

// IfaceStats is aggregated interface stats.
type IfaceStats struct {
	Name       string
	PublicKey  string
	Up         bool
	ListenPort int
	PeerCount  int
	RxBytes    int64
	TxBytes    int64
	RxBps      float64
	TxBps      float64
	UpdatedAt  time.Time
}

// PeerStats is per-peer stats.
type PeerStats struct {
	Interface         string
	PublicKey         string
	Name              string
	Endpoint          string
	AllowedIPs        []string
	LastHandshake     time.Time
	Connected         bool
	ConnectedSince    time.Time
	RxBytes           int64
	TxBytes           int64
	RxBps             float64
	TxBps             float64
	Suspended         bool
	TrafficLimitBytes int64
	BandwidthRxBps    int64
	BandwidthTxBps    int64
	UpdatedAt         time.Time
}

// NewCache creates an empty cache.
func NewCache() *Cache {
	return &Cache{
		ifaces: make(map[string]*IfaceStats),
		peers:  make(map[string]*PeerStats),
	}
}

func peerKey(iface, pub string) string { return iface + "/" + pub }

// SetInterface stores interface stats.
func (c *Cache) SetInterface(s IfaceStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := s
	c.ifaces[s.Name] = &cp
}

// SetPeer stores peer stats.
func (c *Cache) SetPeer(s PeerStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := s
	cp.AllowedIPs = append([]string(nil), s.AllowedIPs...)
	c.peers[peerKey(s.Interface, s.PublicKey)] = &cp
}

// Snapshot returns copies of all stats.
// Peer AllowedIPs slices are deep-copied so callers cannot race the cache.
func (c *Cache) Snapshot() (map[string]IfaceStats, map[string]PeerStats) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	ifaces := make(map[string]IfaceStats, len(c.ifaces))
	for k, v := range c.ifaces {
		ifaces[k] = *v
	}
	peers := make(map[string]PeerStats, len(c.peers))
	for k, v := range c.peers {
		cp := *v
		cp.AllowedIPs = append([]string(nil), v.AllowedIPs...)
		peers[k] = cp
	}
	return ifaces, peers
}

// Clear removes all entries.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ifaces = make(map[string]*IfaceStats)
	c.peers = make(map[string]*PeerStats)
}

// Retain keeps only the given interface and peer keys (iface/pubkey).
func (c *Cache) Retain(ifaces map[string]struct{}, peerKeys map[string]struct{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.ifaces {
		if _, ok := ifaces[k]; !ok {
			delete(c.ifaces, k)
		}
	}
	for k := range c.peers {
		if _, ok := peerKeys[k]; !ok {
			delete(c.peers, k)
		}
	}
}
