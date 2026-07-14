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

// PeerStats is per-peer stats (accumulative totals + time-based rates/windows).
type PeerStats struct {
	Interface         string
	PublicKey         string
	Name              string
	Endpoint          string
	AllowedIPs        []string
	LastHandshake     time.Time
	Connected         bool
	ConnectedSince    time.Time
	RxBytes           int64 // accumulative (since soft-reset)
	TxBytes           int64
	RxBps             float64 // EWMA rate
	TxBps             float64
	RxBpsRaw          float64 // last-interval rate
	TxBpsRaw          float64
	IntervalSec       float64
	Windows           map[string]WindowCounters // "1m","5m","15m","1h","24h"
	Suspended         bool
	TrafficLimitBytes int64
	BandwidthRxBps    int64
	BandwidthTxBps    int64
	UpdatedAt         time.Time
}

// Traffic returns the dual counter view for this peer.
func (p PeerStats) Traffic() Traffic {
	return BuildTraffic(p.RxBytes, p.TxBytes, Rates{
		RxBps: p.RxBps, TxBps: p.TxBps,
		RxBpsRaw: p.RxBpsRaw, TxBpsRaw: p.TxBpsRaw,
		IntervalSec: p.IntervalSec,
	}, p.Windows)
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
	if s.Windows != nil {
		cp.Windows = copyWindows(s.Windows)
	}
	c.peers[peerKey(s.Interface, s.PublicKey)] = &cp
}

func copyWindows(in map[string]WindowCounters) map[string]WindowCounters {
	if in == nil {
		return nil
	}
	out := make(map[string]WindowCounters, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// GetPeer returns a copy of one peer's stats, if present.
func (c *Cache) GetPeer(iface, pubkey string) (PeerStats, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	p, ok := c.peers[peerKey(iface, pubkey)]
	if !ok || p == nil {
		return PeerStats{}, false
	}
	cp := *p
	cp.AllowedIPs = append([]string(nil), p.AllowedIPs...)
	cp.Windows = copyWindows(p.Windows)
	return cp, true
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
		cp.Windows = copyWindows(v.Windows)
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
