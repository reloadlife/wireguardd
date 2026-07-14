package db

import "time"

// Interface is the desired WireGuard interface configuration.
type Interface struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	PrivateKey       string    `json:"private_key,omitempty"`
	PublicKey        string    `json:"public_key"`
	ListenPort       int       `json:"listen_port"`
	FwMark           int       `json:"fwmark"`
	MTU              int       `json:"mtu"`
	TableMode        string    `json:"table_mode"`
	TableID          *int      `json:"table_id,omitempty"`
	DNS              []string  `json:"dns"`
	Addresses        []string  `json:"addresses"`
	PreUp            string    `json:"pre_up,omitempty"`
	PostUp           string    `json:"post_up,omitempty"`
	PreDown          string    `json:"pre_down,omitempty"`
	PostDown         string    `json:"post_down,omitempty"`
	DefaultKeepalive int       `json:"default_keepalive"`
	PublicEndpoint   string    `json:"public_endpoint,omitempty"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// Peer is the desired peer configuration plus observed stats.
type Peer struct {
	ID                  int64     `json:"id"`
	InterfaceID         int64     `json:"interface_id"`
	InterfaceName       string    `json:"interface_name,omitempty"`
	PublicKey           string    `json:"public_key"`
	PresharedKey        string    `json:"preshared_key,omitempty"`
	ClientPrivateKey    string    `json:"client_private_key,omitempty"`
	Name                string    `json:"name"`
	Notes               string    `json:"notes"`
	AllowedIPs          []string  `json:"allowed_ips"`
	AssignedIPs         []string  `json:"assigned_ips"`
	Endpoint            string    `json:"endpoint"`
	PersistentKeepalive int       `json:"persistent_keepalive"`
	Suspended           bool      `json:"suspended"`
	TrafficLimitBytes   int64     `json:"traffic_limit_bytes"`
	BandwidthRxBps      int64     `json:"bandwidth_rx_bps"`
	BandwidthTxBps      int64     `json:"bandwidth_tx_bps"`
	RxBytesOffset       int64     `json:"-"`
	TxBytesOffset       int64     `json:"-"`
	FirstHandshakeAt    string    `json:"first_handshake_at,omitempty"`
	LastHandshakeAt     string    `json:"last_handshake_at,omitempty"`
	ConnectedSince      string    `json:"connected_since,omitempty"`
	LastEndpoint        string    `json:"last_endpoint,omitempty"`
	LastRxBytes         int64     `json:"last_rx_bytes"`
	LastTxBytes         int64     `json:"last_tx_bytes"`
	LastRxBps           float64   `json:"last_rx_bps"`
	LastTxBps           float64   `json:"last_tx_bps"`
	Tags                []string  `json:"tags"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// EffectiveRx returns user-visible received bytes after soft reset.
func (p Peer) EffectiveRx() int64 {
	v := p.LastRxBytes - p.RxBytesOffset
	if v < 0 {
		return 0
	}
	return v
}

// EffectiveTx returns user-visible transmitted bytes after soft reset.
func (p Peer) EffectiveTx() int64 {
	v := p.LastTxBytes - p.TxBytesOffset
	if v < 0 {
		return 0
	}
	return v
}

// Event is an audit or enforcement record.
type Event struct {
	ID            int64     `json:"id"`
	TS            time.Time `json:"ts"`
	Level         string    `json:"level"`
	Kind          string    `json:"kind"`
	Interface     string    `json:"interface,omitempty"`
	PeerPublicKey string    `json:"peer_public_key,omitempty"`
	Message       string    `json:"message"`
	Meta          string    `json:"meta,omitempty"`
}

// TrafficSample is a rate/counter sample for a peer.
type TrafficSample struct {
	ID        int64
	PeerID    int64
	SampledAt time.Time
	RxBytes   int64
	TxBytes   int64
	RxBps     float64
	TxBps     float64
}
