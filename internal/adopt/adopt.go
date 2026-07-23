package adopt

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/reloadlife/wireguardd/internal/confparse"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/netutil"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

// Options control discovery / adopt behaviour.
type Options struct {
	// Names limits adoption to these interface names (empty = all live WireGuard devices).
	Names []string
	// ReadConf merges /etc/wireguard/<name>.conf when present (keys, DNS, Table, hooks, peer comments).
	ReadConf bool
	// ConfDir is the wg-quick conf directory (default /etc/wireguard).
	ConfDir string
	// Overwrite updates peers/config for interfaces already in the DB.
	// When false, existing DB interfaces are skipped (reported as skipped).
	Overwrite bool
}

// Preview is one live device as it would be imported (no DB writes).
type Preview struct {
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

// Adopt imports live WireGuard interfaces into SQLite without removing host peers,
// addresses, routes, or keys. Comment metadata from conf files is preserved.
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
		// Never adopt host-managed control-plane mesh (mesh0). Importing it
		// lets reconcile rewrite peers/keys and take the node offline from CP.
		if netutil.ReservedHostInterface(dev.Name) {
			s.log.Info("adopt skip reserved host interface", "iface", dev.Name)
			continue
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
	addrs := filterAddrs(append([]string(nil), dev.Addresses...))

	listenPort := dev.ListenPort
	fwmark := dev.FirewallMark
	mtu := dev.MTU
	dns := []string{}
	// Prefer leaving routing alone; conf Table= is stored for export but route sync
	// treats non-auto/number as off.
	tableMode := "off"
	var tableID *int
	preUp, postUp, preDown, postDown := "", "", "", ""
	publicEndpoint := ""
	confPath := ""
	confLoaded := false
	var conf *confparse.Config

	if opts.ReadConf {
		path := filepath.Join(opts.ConfDir, dev.Name+".conf")
		if raw, err := os.ReadFile(path); err == nil {
			confPath = path
			parsed, err := confparse.Parse(string(raw))
			if err != nil {
				notes = append(notes, "conf parse error: "+err.Error())
			} else {
				conf = parsed
				confLoaded = true
				if parsed.Interface.PrivateKey != "" && !wgbackend.IsZeroKey(parsed.Interface.PrivateKey) {
					priv = parsed.Interface.PrivateKey
					if p, err := crypto.PublicFromPrivate(priv); err == nil {
						pub = p
					}
				}
				if parsed.Interface.PublicKeyComment != "" {
					pub = parsed.Interface.PublicKeyComment
				}
				if len(parsed.Interface.Address) > 0 {
					addrs = append([]string(nil), parsed.Interface.Address...)
				}
				if parsed.Interface.ListenPort > 0 {
					listenPort = parsed.Interface.ListenPort
				}
				if parsed.Interface.FwMark > 0 {
					fwmark = parsed.Interface.FwMark
				}
				if parsed.Interface.MTU > 0 {
					mtu = parsed.Interface.MTU
				}
				if len(parsed.Interface.DNS) > 0 {
					dns = append([]string(nil), parsed.Interface.DNS...)
				}
				preUp, postUp = parsed.Interface.PreUp, parsed.Interface.PostUp
				preDown, postDown = parsed.Interface.PreDown, parsed.Interface.PostDown
				if parsed.Interface.PeerEndpoint != "" {
					publicEndpoint = parsed.Interface.PeerEndpoint
				}
				if parsed.Interface.Table != "" {
					tableMode, tableID = mapTable(parsed.Interface.Table)
				}
			}
		}
	}

	if priv == "" {
		notes = append(notes, "private key unavailable — stats/peers OK; cannot rotate key or rewrite conf PrivateKey")
	}
	if tableMode != "auto" && tableMode != "number" {
		notes = append(notes, "table_mode="+tableMode+" (route install left to host hooks / off)")
	}

	existing, err := s.store.GetInterfaceByName(ctx, dev.Name)
	already := err == nil && existing != nil

	iface := &db.Interface{
		Name:           dev.Name,
		PrivateKey:     priv,
		PublicKey:      pub,
		ListenPort:     listenPort,
		FwMark:         fwmark,
		MTU:            mtu,
		TableMode:      tableMode,
		TableID:        tableID,
		DNS:            dns,
		Addresses:      addrs,
		PreUp:          preUp,
		PostUp:         postUp,
		PreDown:        preDown,
		PostDown:       postDown,
		PublicEndpoint: publicEndpoint,
		Enabled:        true,
	}
	if already {
		iface.ID = existing.ID
		if iface.PublicEndpoint == "" {
			iface.PublicEndpoint = existing.PublicEndpoint
		}
		iface.DefaultKeepalive = existing.DefaultKeepalive
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
		p := db.Peer{
			PublicKey:           lp.PublicKey,
			PresharedKey:        lp.PresharedKey,
			AllowedIPs:          append([]string(nil), lp.AllowedIPs...),
			AssignedIPs:         assigned,
			Endpoint:            lp.Endpoint,
			PersistentKeepalive: ka,
			LastEndpoint:        lp.Endpoint,
			LastRxBytes:         lp.ReceiveBytes,
			LastTxBytes:         lp.TransmitBytes,
		}
		if !lp.LastHandshakeTime.IsZero() {
			hs := lp.LastHandshakeTime.UTC().Format(time.RFC3339Nano)
			p.LastHandshakeAt = hs
			p.FirstHandshakeAt = hs
		}
		peers = append(peers, p)
	}

	// Enrich from conf comments + peer stanzas (Name, Address, DNS, TrafficLimit, PSK).
	if conf != nil {
		byPub := map[string]confparse.PeerSection{}
		for _, cp := range conf.Peers {
			byPub[cp.PublicKey] = cp
		}
		for i := range peers {
			cp, ok := byPub[peers[i].PublicKey]
			if !ok {
				continue
			}
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
			if cp.Name != "" {
				peers[i].Name = cp.Name
			}
			if cp.Notes != "" {
				peers[i].Notes = cp.Notes
			}
			// Import traffic limits as metadata, but soft-reset counters so existing
			// lifetime kernel totals don't immediately auto-suspend peers on adopt.
			if cp.TrafficLimit > 0 {
				peers[i].TrafficLimitBytes = cp.TrafficLimit
				peers[i].RxBytesOffset = peers[i].LastRxBytes
				peers[i].TxBytesOffset = peers[i].LastTxBytes
			}
			if cp.ExpiresAt != "" {
				peers[i].ExpiresAt = cp.ExpiresAt
			}
			if cp.Address != "" {
				// "# Address = 172.20.0.2/24" → assigned host IP
				host := strings.Split(cp.Address, "/")[0]
				if host != "" {
					peers[i].AssignedIPs = []string{host}
				}
			}
		}
		// Conf-only peers not in kernel: still import so conf is SoT for offline peers.
		livePubs := map[string]struct{}{}
		for _, p := range peers {
			livePubs[p.PublicKey] = struct{}{}
		}
		for _, cp := range conf.Peers {
			if _, ok := livePubs[cp.PublicKey]; ok {
				continue
			}
			assigned := hostIPsFromAllowed(cp.AllowedIPs)
			if cp.Address != "" {
				host := strings.Split(cp.Address, "/")[0]
				if host != "" {
					assigned = []string{host}
				}
			}
			peers = append(peers, db.Peer{
				PublicKey:           cp.PublicKey,
				PresharedKey:        cp.PresharedKey,
				Name:                cp.Name,
				Notes:               cp.Notes,
				AllowedIPs:          append([]string(nil), cp.AllowedIPs...),
				AssignedIPs:         assigned,
				Endpoint:            cp.Endpoint,
				PersistentKeepalive: cp.PersistentKeepalive,
				TrafficLimitBytes:   cp.TrafficLimit,
				ExpiresAt:           cp.ExpiresAt,
			})
			notes = append(notes, "imported conf-only peer "+short(cp.PublicKey))
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
	if p.preview.AlreadyInDB && !overwrite {
		return nil
	}
	return s.store.ImportInterface(ctx, p.iface, p.peers)
}

// mapTable converts conf Table= into DB table_mode + optional id.
// Custom names (wgvpn, gaming) are stored as-is for conf export; route sync treats them as off.
func mapTable(table string) (mode string, id *int) {
	table = strings.TrimSpace(table)
	switch strings.ToLower(table) {
	case "", "auto":
		return "auto", nil
	case "off":
		return "off", nil
	default:
		if n, err := strconv.Atoi(table); err == nil && n > 0 {
			return "number", &n
		}
		// Preserve custom name for conf persistence.
		return table, nil
	}
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

func short(pub string) string {
	if len(pub) <= 12 {
		return pub
	}
	return pub[:8] + "…"
}
