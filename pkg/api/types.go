package api

import "time"

// ErrorBody is the standard error envelope.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

// ErrorDetail carries machine-readable error info.
type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details any    `json:"details,omitempty"`
}

// VersionInfo is returned by /v1/version.
type VersionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

// InterfaceCreateRequest creates a WireGuard interface.
type InterfaceCreateRequest struct {
	Name             string   `json:"name"`
	PrivateKey       string   `json:"private_key,omitempty"`
	ListenPort       int      `json:"listen_port"`
	FwMark           int      `json:"fwmark"`
	MTU              int      `json:"mtu"`
	TableMode        string   `json:"table_mode,omitempty"`
	TableID          *int     `json:"table_id,omitempty"`
	DNS              []string `json:"dns"`
	Addresses        []string `json:"addresses"`
	PreUp            string   `json:"pre_up,omitempty"`
	PostUp           string   `json:"post_up,omitempty"`
	PreDown          string   `json:"pre_down,omitempty"`
	PostDown         string   `json:"post_down,omitempty"`
	DefaultKeepalive int      `json:"default_keepalive"`
	Enabled          *bool    `json:"enabled,omitempty"`
}

// InterfaceUpdateRequest patches an interface.
type InterfaceUpdateRequest struct {
	PrivateKey       *string  `json:"private_key,omitempty"`
	ListenPort       *int     `json:"listen_port,omitempty"`
	FwMark           *int     `json:"fwmark,omitempty"`
	MTU              *int     `json:"mtu,omitempty"`
	TableMode        *string  `json:"table_mode,omitempty"`
	TableID          *int     `json:"table_id,omitempty"`
	DNS              []string `json:"dns,omitempty"`
	Addresses        []string `json:"addresses,omitempty"`
	PreUp            *string  `json:"pre_up,omitempty"`
	PostUp           *string  `json:"post_up,omitempty"`
	PreDown          *string  `json:"pre_down,omitempty"`
	PostDown         *string  `json:"post_down,omitempty"`
	DefaultKeepalive *int     `json:"default_keepalive,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
}

// Interface is the API representation of an interface.
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
	Enabled          bool      `json:"enabled"`
	Up               bool      `json:"up"`
	PeerCount        int       `json:"peer_count"`
	RxBytes          int64     `json:"rx_bytes"`
	TxBytes          int64     `json:"tx_bytes"`
	RxBps            float64   `json:"rx_bps"`
	TxBps            float64   `json:"tx_bps"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// PeerCreateRequest creates a peer.
type PeerCreateRequest struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	GeneratePSK         bool     `json:"generate_psk,omitempty"`
	Name                string   `json:"name"`
	Notes               string   `json:"notes"`
	AllowedIPs          []string `json:"allowed_ips"`
	AssignedIPs         []string `json:"assigned_ips"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	TrafficLimitBytes   int64    `json:"traffic_limit_bytes"`
	BandwidthRxBps      int64    `json:"bandwidth_rx_bps"`
	BandwidthTxBps      int64    `json:"bandwidth_tx_bps"`
	Tags                []string `json:"tags"`
}

// PeerUpdateRequest patches a peer.
type PeerUpdateRequest struct {
	PresharedKey        *string  `json:"preshared_key,omitempty"`
	Name                *string  `json:"name,omitempty"`
	Notes               *string  `json:"notes,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	AssignedIPs         []string `json:"assigned_ips,omitempty"`
	Endpoint            *string  `json:"endpoint,omitempty"`
	PersistentKeepalive *int     `json:"persistent_keepalive,omitempty"`
	TrafficLimitBytes   *int64   `json:"traffic_limit_bytes,omitempty"`
	BandwidthRxBps      *int64   `json:"bandwidth_rx_bps,omitempty"`
	BandwidthTxBps      *int64   `json:"bandwidth_tx_bps,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	Suspended           *bool    `json:"suspended,omitempty"`
}

// Peer is the API representation of a peer.
type Peer struct {
	ID                  int64     `json:"id"`
	InterfaceName       string    `json:"interface_name"`
	PublicKey           string    `json:"public_key"`
	PresharedKey        string    `json:"preshared_key,omitempty"`
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
	FirstHandshakeAt    string    `json:"first_handshake_at,omitempty"`
	LastHandshakeAt     string    `json:"last_handshake_at,omitempty"`
	ConnectedSince      string    `json:"connected_since,omitempty"`
	LastEndpoint        string    `json:"last_endpoint,omitempty"`
	RxBytes             int64     `json:"rx_bytes"`
	TxBytes             int64     `json:"tx_bytes"`
	RxBps               float64   `json:"rx_bps"`
	TxBps               float64   `json:"tx_bps"`
	Connected           bool      `json:"connected"`
	Tags                []string  `json:"tags"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// KeyGenerateRequest requests key material.
type KeyGenerateRequest struct {
	Type string `json:"type"` // "keypair" | "preshared"
}

// KeyGenerateResponse returns key material.
type KeyGenerateResponse struct {
	PrivateKey   string `json:"private_key,omitempty"`
	PublicKey    string `json:"public_key,omitempty"`
	PresharedKey string `json:"preshared_key,omitempty"`
}

// Event is an audit/enforcement event.
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

// StatsSummary is a global stats rollup.
type StatsSummary struct {
	Interfaces int     `json:"interfaces"`
	Peers      int     `json:"peers"`
	Connected  int     `json:"connected"`
	Suspended  int     `json:"suspended"`
	RxBytes    int64   `json:"rx_bytes"`
	TxBytes    int64   `json:"tx_bytes"`
	RxBps      float64 `json:"rx_bps"`
	TxBps      float64 `json:"tx_bps"`
}

// DaemonConfig is non-secret runtime config.
type DaemonConfig struct {
	HTTPListen         string `json:"http_listen"`
	UnixListen         string `json:"unix_listen"`
	MetricsListen      string `json:"metrics_listen"`
	SNMPEnabled        bool   `json:"snmp_enabled"`
	SNMPListen         string `json:"snmp_listen"`
	Persistence        string `json:"persistence"`
	ConfDir            string `json:"conf_dir"`
	HandshakeConnected int    `json:"handshake_connected_sec"`
	SampleInterval     string `json:"sample_interval"`
	ReconcileInterval  string `json:"reconcile_interval"`
	AllowHooks         bool   `json:"allow_hooks"`
	BandwidthBackend   string `json:"bandwidth_backend"`
	ReadOnly           bool   `json:"read_only"`
}

// ImportConfRequest imports a wg-quick conf body.
type ImportConfRequest struct {
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

// ClientConfigResponse is a client-side conf.
type ClientConfigResponse struct {
	Config string `json:"config"`
}
