package adopt

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/reloadlife/wireguardd/internal/confparse"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

// Options control discovery / adopt behaviour.
type Options struct {
	// Names limits adoption to these interface names (empty = all live WireGuard devices).
	Names []string
	// ReadConf merges /etc/wireguard/<name>.conf when present (keys, DNS, Table, hooks).
	ReadConf bool
	// ConfDir is the wg-quick conf directory (default /etc/wireguard).
	ConfDir string
	// Overwrite updates peers/config for interfaces already in the DB.
	// When false, existing DB interfaces are skipped (reported as skipped).
	Overwrite bool
}

// Preview is one live device as it would be imported (no DB writes).
type Preview struct {
	Name            string   `json:"name"`
	PublicKey       string   `json:"public_key"`
	HasPrivateKey   bool     `json:"has_private_key"`
	ListenPort      int      `json:"listen_port"`
	FwMark          int      `json:"fwmark"`
	MTU             int      `json:"mtu"`
	Addresses       []string `json:"addresses"`
	PeerCount       int      `json:"peer_count"`
	Up              bool     `json:"up"`
	ConfPath        string   `json:"conf_path,omitempty"`
	ConfLoaded      bool     `json:"conf_loaded"`
	AlreadyInDB     bool     `json:"already_in_db"`
	TableMode       string   `json:"table_mode"`
	Notes           []string `json:"notes,omitempty"`
}

// Result is the outcome for one interface after Adopt.
type Result struct {
	Name          string   `json:"name"`
	Action        string   `json:"action"` // created | updated | skipped | error
	HasPrivateKey bool     `json:"has_private_key"`
	PeerCount     int      `json:"peer_count"`
	ConfLoaded    bool     `json:"conf_loaded"`
	Error         string   `json:"error,omitempty"`
	Notes         []string `json:"notes,omitempty"`
}

// Report is the full adopt/discover response.
type Report struct {
	At      time.Time `json:"at"`
	Preview []Preview `json:"preview,omitempty"`
	Results []Result  `json:"results,omitempty"`
}

// Service discovers live WireGuard and imports it into the DB without tearing host state down.
type Service struct {
	store   *db.Store
	backend wgbackend.Backend
	confDir string
	log     *slog.Logger
}

// New creates an adopt service.
func New(store *db.Store, backend wgbackend.Backend, confDir string, log *slog.Logger) *Service {
	if confDir == "" {
		confDir = "/etc/wireguard"
	}
	if log == nil {
		log = slog.Default()
	}
	return &Service{store: store, backend: backend, confDir: confDir, log: log}
}

// Discover lists live devices and how they would map into the DB (read-only).
func (s *Service) Discover(ctx context.Context, opts Options) (*Report, error) {
	opts = s.normalize(opts)
	plans, err := s.plan(ctx, opts)
	if err != nil {
		return nil, err
	}
	rep := &Report{At: time.Now().UTC()}
	for _, p := range plans {
		rep.Preview = append(rep.Preview, p.preview)
	}
	return rep, nil
}

// Adopt imports live WireGuard interfaces into SQLite (source of truth) without
// removing host peers, addresses, routes, or keys.
func (s *Service) Adopt(ctx context.Context, opts Options) (*Report, error) {
	opts = s.normalize(opts)
	plans, err := s.plan(ctx, opts)
	if err != nil {
		return nil, err
	}
	rep := &Report{At: time.Now().UTC()}
	for _, p := range plans {
		rep.Preview = append(rep.Preview, p.preview)
		res := Result{
			Name:          p.preview.Name,
			HasPrivateKey: p.preview.HasPrivateKey,
			PeerCount:     p.preview.PeerCount,
			ConfLoaded:    p.preview.ConfLoaded,
			Notes:         append([]string(nil), p.preview.Notes...),
		}
		if p.preview.AlreadyInDB && !opts.Overwrite {
			res.Action = "skipped"
			res.Notes = append(res.Notes, "already in database (pass overwrite to refresh)")
			rep.Results = append(rep.Results, res)
			continue
		}
		if err := s.applyPlan(ctx, p, opts.Overwrite); err != nil {
			res.Action = "error"
			res.Error = err.Error()
			s.log.Error("adopt interface", "iface", p.preview.Name, "err", err)
		} else if p.preview.AlreadyInDB {
			res.Action = "updated"
		} else {
			res.Action = "created"
		}
		rep.Results = append(rep.Results, res)
	}
	_ = s.store.AddEvent(ctx, "info", "audit", "", "",
		fmt.Sprintf("adopt finished: %d device(s)", len(rep.Results)), "{}")
	return rep, nil
}

func (s *Service) normalize(opts Options) Options {
	if opts.ConfDir == "" {
		opts.ConfDir = s.confDir
	}
	// Default: try conf files — best source of private keys / Address= / DNS=.
	if !opts.ReadConf {
		// zero value false — callers that want conf must set true; we default true via API.
	}
	return opts
}

type plan struct {
	preview Preview
	iface   *db.Interface
	peers   []db.Peer
}

func (s *Service) plan(ctx context.Context, opts Options) ([]plan, error) {
	live, err := s.backend.Devices(ctx)
	if err != nil {
		return nil, fmt.Errorf("list live devices: %w", err)
	}
	want := map[string]struct{}{}
	for _, n := range opts.Names {
		n = strings.TrimSpace(n)
		if n != "" {
			want[n] = struct{}{}
		}
	}
	var out []plan
	for _, dev := range live {
		if len(want) > 0 {
			if _, ok := want[dev.Name]; !ok {
				continue
			}
		}
		p, err := s.buildPlan(ctx, dev, opts)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func (s *Service) buildPlan(ctx context.Context, dev wgbackend.Device, opts Options) (plan, error) {
	notes := []string{}
	priv := dev.PrivateKey
	if wgbackend.IsZeroKey(priv) {
		priv = ""
	}
	pub := dev.PublicKey
	addrs := append([]string(nil), dev.Addresses...)
	// Filter link-local from stored addresses
	addrs = filterAddrs(addrs)

	listenPort := dev.ListenPort
	fwmark := dev.FirewallMark
	mtu := dev.MTU
	dns := []string{}
	tableMode := "off" // safest: do not rewrite host routes on first adopt
	var tableID *int
	preUp, postUp, preDown, postDown := "", "", "", ""
	confPath := ""
	confLoaded := false

	if opts.ReadConf {
		path := filepath.Join(opts.ConfDir, dev.Name+".conf")
		confPath = path
		if raw, err := os.ReadFile(path); err == nil {
			cfg, err := confparse.Parse(string(raw))
			if err != nil {
				notes = append(notes, "conf parse error: "+err.Error())
			} else {
				confLoaded = true
				if cfg.Interface.PrivateKey != "" && !wgbackend.IsZeroKey(cfg.Interface.PrivateKey) {
					priv = cfg.Interface.PrivateKey
					if p, err := crypto.PublicFromPrivate(priv); err == nil {
						pub = p
					}
				}
				if len(cfg.Interface.Address) > 0 {
					addrs = append([]string(nil), cfg.Interface.Address...)
				}
				if cfg.Interface.ListenPort > 0 {
					listenPort = cfg.Interface.ListenPort
				}
				if cfg.Interface.FwMark > 0 {
					fwmark = cfg.Interface.FwMark
				}
				if cfg.Interface.MTU > 0 {
					mtu = cfg.Interface.MTU
				}
				if len(cfg.Interface.DNS) > 0 {
					dns = append([]string(nil), cfg.Interface.DNS...)
				}
				preUp, postUp = cfg.Interface.PreUp, cfg.Interface.PostUp
				preDown, postDown = cfg.Interface.PreDown, cfg.Interface.PostDown
				if cfg.Interface.Table != "" {
					switch strings.ToLower(cfg.Interface.Table) {
					case "off", "auto":
						tableMode = strings.ToLower(cfg.Interface.Table)
					default:
						tableMode = "number"
						var n int
						fmt.Sscanf(cfg.Interface.Table, "%d", &n)
						if n > 0 {
							tableID = &n
						} else {
							tableMode = "off"
							notes = append(notes, "invalid Table= in conf, using off")
						}
					}
				}
				// Merge conf peers that may have richer AllowedIPs/Endpoint than kernel
				// (kernel is still source of truth for membership; conf fills gaps).
				_ = cfg
			}
		} else {
			confPath = ""
		}
	}

	if priv == "" {
		notes = append(notes, "private key unavailable — stats/peers OK; cannot rotate key or rewrite conf PrivateKey")
	}
	if tableMode == "off" {
		notes = append(notes, "table_mode=off (will not install/remove routes until changed)")
	}

	existing, err := s.store.GetInterfaceByName(ctx, dev.Name)
	already := err == nil && existing != nil

	iface := &db.Interface{
		Name:       dev.Name,
		PrivateKey: priv,
		PublicKey:  pub,
		ListenPort: listenPort,
		FwMark:     fwmark,
		MTU:        mtu,
		TableMode:  tableMode,
		TableID:    tableID,
		DNS:        dns,
		Addresses:  addrs,
		PreUp:      preUp,
		PostUp:     postUp,
		PreDown:    preDown,
		PostDown:   postDown,
		Enabled:    true, // keep managing as up; SetUp(true) is idempotent
	}
	if already {
		iface.ID = existing.ID
		// Preserve operator-set public_endpoint / default_keepalive when refreshing.
		iface.PublicEndpoint = existing.PublicEndpoint
		iface.DefaultKeepalive = existing.DefaultKeepalive
		if !opts.Overwrite {
			// still build peers for preview peer_count
		}
	}
	if iface.PublicKey == "" && priv != "" {
		if p, err := crypto.PublicFromPrivate(priv); err == nil {
			iface.PublicKey = p
		}
	}

	// Peers from live kernel (authoritative membership).
	peers := make([]db.Peer, 0, len(dev.Peers))
	for _, lp := range dev.Peers {
		ka := int(lp.PersistentKeepaliveInterval / time.Second)
		assigned := hostIPsFromAllowed(lp.AllowedIPs)
		peers = append(peers, db.Peer{
			PublicKey:           lp.PublicKey,
			PresharedKey:        lp.PresharedKey,
			AllowedIPs:          append([]string(nil), lp.AllowedIPs...),
			AssignedIPs:         assigned,
			Endpoint:            lp.Endpoint,
			PersistentKeepalive: ka,
			LastEndpoint:        lp.Endpoint,
			LastRxBytes:         lp.ReceiveBytes,
			LastTxBytes:         lp.TransmitBytes,
		})
		if !lp.LastHandshakeTime.IsZero() {
			peers[len(peers)-1].LastHandshakeAt = lp.LastHandshakeTime.UTC().Format(time.RFC3339Nano)
			peers[len(peers)-1].FirstHandshakeAt = peers[len(peers)-1].LastHandshakeAt
		}
	}

	// Optional: enrich peer PSK/endpoint from conf when kernel lacks them.
	if confLoaded && opts.ReadConf {
		path := filepath.Join(opts.ConfDir, dev.Name+".conf")
		if raw, err := os.ReadFile(path); err == nil {
			if cfg, err := confparse.Parse(string(raw)); err == nil {
				byPub := map[string]confparse.PeerSection{}
				for _, cp := range cfg.Peers {
					byPub[cp.PublicKey] = cp
				}
				for i := range peers {
					if cp, ok := byPub[peers[i].PublicKey]; ok {
						if peers[i].PresharedKey == "" && cp.PresharedKey != "" {
							peers[i].PresharedKey = cp.PresharedKey
						}
						if peers[i].Endpoint == "" && cp.Endpoint != "" {
							peers[i].Endpoint = cp.Endpoint
						}
						if len(peers[i].AllowedIPs) == 0 && len(cp.AllowedIPs) > 0 {
							peers[i].AllowedIPs = append([]string(nil), cp.AllowedIPs...)
						}
						if peers[i].PersistentKeepalive == 0 && cp.PersistentKeepalive > 0 {
							peers[i].PersistentKeepalive = cp.PersistentKeepalive
						}
					}
				}
			}
		}
	}

	prev := Preview{
		Name:          dev.Name,
		PublicKey:     iface.PublicKey,
		HasPrivateKey: priv != "",
		ListenPort:    listenPort,
		FwMark:        fwmark,
		MTU:           mtu,
		Addresses:     addrs,
		PeerCount:     len(peers),
		Up:            dev.Up,
		ConfPath:      confPath,
		ConfLoaded:    confLoaded,
		AlreadyInDB:   already,
		TableMode:     tableMode,
		Notes:         notes,
	}
	return plan{preview: prev, iface: iface, peers: peers}, nil
}

func (s *Service) applyPlan(ctx context.Context, p plan, overwrite bool) error {
	// ImportInterface does atomic upsert of iface + full peer replace in state DB.
	// That matches live peer set — ApplyPeers later won't delete kernel peers.
	if p.preview.AlreadyInDB && !overwrite {
		return nil
	}
	return s.store.ImportInterface(ctx, p.iface, p.peers)
}

func filterAddrs(in []string) []string {
	var out []string
	for _, a := range in {
		a = strings.TrimSpace(a)
		if a == "" || strings.HasPrefix(a, "fe80:") || strings.HasPrefix(a, "fe80::") {
			continue
		}
		out = append(out, a)
	}
	return out
}

// hostIPsFromAllowed picks /32 and /128 from AllowedIPs as assigned_ips candidates.
func hostIPsFromAllowed(allowed []string) []string {
	var out []string
	for _, a := range allowed {
		if strings.HasSuffix(a, "/32") {
			out = append(out, strings.TrimSuffix(a, "/32"))
		} else if strings.HasSuffix(a, "/128") {
			out = append(out, strings.TrimSuffix(a, "/128"))
		}
	}
	return out
}
