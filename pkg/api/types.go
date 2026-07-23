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

// AmneziaParams are interface-level AmneziaWG obfuscation parameters.
// S* and H* must match client and server; Jc/Jmin/Jmax may differ (often client-only).
type AmneziaParams struct {
	Jc   int    `json:"jc,omitempty"`
	Jmin int    `json:"jmin,omitempty"`
	Jmax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	S3   int    `json:"s3,omitempty"`
	S4   int    `json:"s4,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
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
	PublicEndpoint   string   `json:"public_endpoint,omitempty"` // host:port advertised to clients
	Enabled          *bool    `json:"enabled,omitempty"`
	// Backend: auto | kernel | userspace | amnezia_kernel | amnezia_go
	Backend string `json:"backend,omitempty"`
	// Protocol: wg | awg
	Protocol string `json:"protocol,omitempty"`
	// Amnezia params (required shape for protocol=awg; auto-generated when empty).
	Amnezia *AmneziaParams `json:"amnezia,omitempty"`
	// CreateAWGPair creates a sibling AWG interface on listen_port+10 (default dual ingress).
	CreateAWGPair bool `json:"create_awg_pair,omitempty"`
	// AWGName overrides the twin name (default derived from name).
	AWGName string `json:"awg_name,omitempty"`
	// AWGAddresses for the twin; empty leaves addresses unset on the AWG iface.
	AWGAddresses []string `json:"awg_addresses,omitempty"`
	// AWGBackend overrides twin backend (default auto → amnezia_kernel preferred).
	AWGBackend string `json:"awg_backend,omitempty"`
	// AWGAmnezia overrides twin noise (default: generated noise preset).
	AWGAmnezia *AmneziaParams `json:"awg_amnezia,omitempty"`
	// NeutralAWG forces H=1..4 S=0 dual-compat mode on the AWG twin.
	NeutralAWG bool `json:"neutral_awg,omitempty"`
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
	PublicEndpoint   *string  `json:"public_endpoint,omitempty"`
	Enabled          *bool    `json:"enabled,omitempty"`
	Backend          *string  `json:"backend,omitempty"`
	Protocol         *string  `json:"protocol,omitempty"`
	Amnezia          *AmneziaParams `json:"amnezia,omitempty"`
	PairName         *string  `json:"pair_name,omitempty"`
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
	PublicEndpoint   string    `json:"public_endpoint,omitempty"`
	Enabled          bool      `json:"enabled"`
	Up               bool      `json:"up"`
	PeerCount        int       `json:"peer_count"`
	RxBytes          int64     `json:"rx_bytes"`
	TxBytes          int64     `json:"tx_bytes"`
	RxBps            float64   `json:"rx_bps"`
	TxBps            float64   `json:"tx_bps"`
	// Backend desired: auto|kernel|userspace|amnezia_kernel|amnezia_go
	Backend string `json:"backend,omitempty"`
	// ResolvedBackend is the live/detected backend when known.
	ResolvedBackend string `json:"resolved_backend,omitempty"`
	// Protocol: wg | awg
	Protocol string `json:"protocol,omitempty"`
	// Amnezia params when protocol=awg (or amnezia backend).
	Amnezia *AmneziaParams `json:"amnezia,omitempty"`
	// PairName is the linked twin interface (WG ↔ AWG).
	PairName  string    `json:"pair_name,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// InterfacePairResponse is returned when create_awg_pair creates both interfaces.
type InterfacePairResponse struct {
	WG  Interface `json:"wg"`
	AWG Interface `json:"awg"`
}

// BackendCapabilities describes which host backends are available.
type BackendCapabilities struct {
	KernelWG         bool `json:"kernel_wg"`
	UserspaceWG      bool `json:"userspace_wg"`
	KernelAmnezia    bool `json:"kernel_amnezia"`
	UserspaceAmnezia bool `json:"userspace_amnezia"`
	AWGTool          bool `json:"awg_tool"`
}

// PeerCreateRequest creates a peer.
type PeerCreateRequest struct {
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	GeneratePSK         bool     `json:"generate_psk,omitempty"`
	GenerateClientKey   bool     `json:"generate_client_key,omitempty"` // store client private key for conf/QR
	ClientPrivateKey    string   `json:"client_private_key,omitempty"`
	Name                string   `json:"name"`
	Notes               string   `json:"notes"`
	AllowedIPs          []string `json:"allowed_ips"`
	AssignedIPs         []string `json:"assigned_ips"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	TrafficLimitBytes   int64    `json:"traffic_limit_bytes"`
	// ExpiresAt is RFC3339 (empty = never). When past, reconciler auto-suspends.
	ExpiresAt      string `json:"expires_at,omitempty"`
	BandwidthRxBps int64  `json:"bandwidth_rx_bps"`
	BandwidthTxBps int64  `json:"bandwidth_tx_bps"`
	// BandwidthTotalBps applies to both directions when a side is 0 (bytes/sec).
	BandwidthTotalBps int64    `json:"bandwidth_total_bps"`
	Tags              []string `json:"tags"`
}

// PeerUpdateRequest patches a peer.
type PeerUpdateRequest struct {
	PresharedKey        *string  `json:"preshared_key,omitempty"`
	ClientPrivateKey    *string  `json:"client_private_key,omitempty"` // must match public_key if set
	Name                *string  `json:"name,omitempty"`
	Notes               *string  `json:"notes,omitempty"`
	AllowedIPs          []string `json:"allowed_ips,omitempty"`
	AssignedIPs         []string `json:"assigned_ips,omitempty"`
	Endpoint            *string  `json:"endpoint,omitempty"`
	PersistentKeepalive *int     `json:"persistent_keepalive,omitempty"`
	TrafficLimitBytes   *int64   `json:"traffic_limit_bytes,omitempty"`
	ExpiresAt           *string  `json:"expires_at,omitempty"` // RFC3339 or "" to clear
	BandwidthRxBps      *int64   `json:"bandwidth_rx_bps,omitempty"`
	BandwidthTxBps      *int64   `json:"bandwidth_tx_bps,omitempty"`
	BandwidthTotalBps   *int64   `json:"bandwidth_total_bps,omitempty"`
	Tags                []string `json:"tags,omitempty"`
	Suspended           *bool    `json:"suspended,omitempty"`
}

// IssueClientKeyRequest controls client key issuance for an existing peer.
type IssueClientKeyRequest struct {
	// Rotate replaces the peer public key with a newly generated keypair.
	// Required for adopted peers (server never has the original client private key).
	// The existing client must re-import the new config.
	Rotate bool `json:"rotate"`
}

// IssueClientKeyResponse returns the new peer identity and ready-to-use client conf.
type IssueClientKeyResponse struct {
	Peer              Peer   `json:"peer"`
	ClientPrivateKey  string `json:"client_private_key"`
	PreviousPublicKey string `json:"previous_public_key,omitempty"`
	Config            string `json:"config"`
	Rotated           bool   `json:"rotated"`
}

// Peer is the API representation of a peer.
type Peer struct {
	ID                  int64    `json:"id"`
	InterfaceName       string   `json:"interface_name"`
	PublicKey           string   `json:"public_key"`
	PresharedKey        string   `json:"preshared_key,omitempty"`
	Name                string   `json:"name"`
	Notes               string   `json:"notes"`
	AllowedIPs          []string `json:"allowed_ips"`
	AssignedIPs         []string `json:"assigned_ips"`
	Endpoint            string   `json:"endpoint"`
	PersistentKeepalive int      `json:"persistent_keepalive"`
	Suspended           bool     `json:"suspended"`
	TrafficLimitBytes   int64    `json:"traffic_limit_bytes"`
	ExpiresAt           string   `json:"expires_at,omitempty"`
	BandwidthRxBps      int64    `json:"bandwidth_rx_bps"`
	BandwidthTxBps      int64    `json:"bandwidth_tx_bps"`
	BandwidthTotalBps   int64    `json:"bandwidth_total_bps"`
	FirstHandshakeAt    string   `json:"first_handshake_at,omitempty"`
	LastHandshakeAt     string   `json:"last_handshake_at,omitempty"`
	ConnectedSince      string   `json:"connected_since,omitempty"`
	LastEndpoint        string   `json:"last_endpoint,omitempty"`
	// Flat counters kept for compatibility (same as traffic.total / traffic.rate EWMA).
	RxBytes int64   `json:"rx_bytes"` // accumulative since soft-reset
	TxBytes int64   `json:"tx_bytes"`
	RxBps   float64 `json:"rx_bps"` // EWMA rate (bytes/sec)
	TxBps   float64 `json:"tx_bps"`
	// Traffic is the dual model: accumulative totals + time-based rates + lookback windows.
	Traffic   PeerTraffic `json:"traffic"`
	Connected bool        `json:"connected"`
	Tags      []string    `json:"tags"`
	CreatedAt time.Time   `json:"created_at"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// PeerTraffic dual counter model for a peer.
type PeerTraffic struct {
	// Total is accumulative bytes since soft-reset (or peer creation).
	Total TrafficBytes `json:"total"`
	// Rate is current time-based throughput.
	Rate TrafficRates `json:"rate"`
	// Windows are bytes transferred over fixed lookbacks (1m,5m,15m,1h,24h).
	Windows map[string]TrafficWindow `json:"windows,omitempty"`
}

// TrafficBytes is an accumulative byte pair.
type TrafficBytes struct {
	RxBytes int64 `json:"rx_bytes"`
	TxBytes int64 `json:"tx_bytes"`
}

// TrafficRates is time-based throughput (bytes/sec).
type TrafficRates struct {
	RxBps       float64 `json:"rx_bps"`                 // EWMA-smoothed
	TxBps       float64 `json:"tx_bps"`                 // EWMA-smoothed
	RxBpsRaw    float64 `json:"rx_bps_raw"`             // last sample interval
	TxBpsRaw    float64 `json:"tx_bps_raw"`             // last sample interval
	IntervalSec float64 `json:"interval_sec,omitempty"` // last sample duration
}

// TrafficWindow is period traffic (delta over a lookback) + average rate.
type TrafficWindow struct {
	RxBytes  int64   `json:"rx_bytes"`
	TxBytes  int64   `json:"tx_bytes"`
	RxBpsAvg float64 `json:"rx_bps_avg"`
	TxBpsAvg float64 `json:"tx_bps_avg"`
	SpanSec  float64 `json:"span_sec,omitempty"`
}

// PeerTrafficHistory is a time series of samples for graphing.
type PeerTrafficHistory struct {
	Interface string    `json:"interface"`
	PublicKey string    `json:"public_key"`
	From      time.Time `json:"from"`
	To        time.Time `json:"to"`
	// Traffic dual snapshot at "to" (totals + rates + windows).
	Traffic PeerTraffic `json:"traffic"`
	// Samples are accumulative totals and rates at each sample point.
	Samples []TrafficSamplePoint `json:"samples"`
}

// TrafficSamplePoint is one historical observation.
type TrafficSamplePoint struct {
	Time    time.Time `json:"time"`
	RxBytes int64     `json:"rx_bytes"` // accumulative at sample time
	TxBytes int64     `json:"tx_bytes"`
	RxBps   float64   `json:"rx_bps"` // rate at sample time
	TxBps   float64   `json:"tx_bps"`
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
	RxBytes    int64   `json:"rx_bytes"` // accumulative
	TxBytes    int64   `json:"tx_bytes"`
	RxBps      float64 `json:"rx_bps"` // current EWMA rate
	TxBps      float64 `json:"tx_bps"`
	// Traffic dual rollup (sum of peer totals + sum of peer rates).
	Traffic PeerTraffic `json:"traffic"`
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
	DBPath             string `json:"db_path,omitempty"`
	TimeseriesPath     string `json:"timeseries_path,omitempty"`
	ReadOnly           bool   `json:"read_only"`
}

// ImportConfRequest imports a wg-quick conf body.
type ImportConfRequest struct {
	Content string `json:"content"`
	Name    string `json:"name,omitempty"`
}

// AdoptRequest adopts live host WireGuard interfaces into the daemon DB.
type AdoptRequest struct {
	// Names limits adoption (empty = all live WireGuard devices).
	Names []string `json:"names,omitempty"`
	// ReadConf merges /etc/wireguard/<name>.conf when present (default true).
	ReadConf *bool `json:"read_conf,omitempty"`
	// Overwrite refreshes interfaces already present in the DB (default false).
	Overwrite bool `json:"overwrite,omitempty"`
}

// AdoptPreview is one live device as discover would import it.
type AdoptPreview struct {
	Name          string   `json:"name"`
	PublicKey     string   `json:"public_key"`
	HasPrivateKey bool     `json:"has_private_key"`
	ListenPort    int      `json:"listen_port"`
	FwMark        int      `json:"fwmark"`
	MTU           int      `json:"mtu"`
	Addresses     []string `json:"addresses"`
	PeerCount     int      `json:"peer_count"`
	Up            bool     `json:"up"`
	ConfPath      string   `json:"conf_path,omitempty"`
	ConfLoaded    bool     `json:"conf_loaded"`
	AlreadyInDB   bool     `json:"already_in_db"`
	TableMode     string   `json:"table_mode"`
	Notes         []string `json:"notes,omitempty"`
}

// AdoptResult is the outcome for one interface after adopt.
type AdoptResult struct {
	Name          string   `json:"name"`
	Action        string   `json:"action"`
	HasPrivateKey bool     `json:"has_private_key"`
	PeerCount     int      `json:"peer_count"`
	ConfLoaded    bool     `json:"conf_loaded"`
	Error         string   `json:"error,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// AdoptReport is returned by discover/adopt endpoints.
type AdoptReport struct {
	At      time.Time      `json:"at"`
	Preview []AdoptPreview `json:"preview,omitempty"`
	Results []AdoptResult  `json:"results,omitempty"`
}

// ClientConfigResponse is a client-side conf.
type ClientConfigResponse struct {
	Config string `json:"config"`
}
