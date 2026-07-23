package confparse

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"
)

// Config is a parsed wg-quick style configuration (plus wireguardd comment metadata).
type Config struct {
	Interface InterfaceSection
	Peers     []PeerSection
}

// InterfaceSection holds [Interface] fields plus durable comment metadata.
type InterfaceSection struct {
	PrivateKey string
	Address    []string
	ListenPort int
	DNS        []string
	MTU        int
	Table      string // "off", "auto", number, or custom name (e.g. wgvpn)
	FwMark     int
	PreUp      string
	PostUp     string // multiple PostUp lines joined with \n
	PreDown    string
	PostDown   string // multiple PostDown lines joined with \n
	SaveConfig bool

	// AmneziaWG interface-level params (optional).
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	S3   int
	S4   int
	H1   string
	H2   string
	H3   string
	H4   string
	I1   string
	I2   string
	I3   string
	I4   string
	I5   string

	// Comment metadata (persisted as # Key = value above the section body).
	PublicKeyComment string // # PublicKey = ...
	PeerDNS          string // # PeerDNS = ... (default client DNS)
	PeerEndpoint     string // # PeerEndpoint = ... (public endpoint for clients)
	Backend          string // # Backend = kernel|userspace|amnezia_kernel|amnezia_go
	Protocol         string // # Protocol = wg|awg
	PairName         string // # PairName = twin interface
}

// PeerSection holds [Peer] fields plus durable comment metadata.
type PeerSection struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int

	// Comment metadata (written immediately above [Peer] for DB-less recovery).
	Name             string // # Name = ...
	Address          string // # Address = 10.0.0.2/24 (client tunnel addr)
	DNS              string // # DNS = 1.1.1.1
	ClientAllowedIPs string // # ClientAllowedIPs = ...
	TrafficLimit     int64  // # TrafficLimit = bytes
	ExpiresAt        string // # ExpiresAt = 2026-12-31T00:00:00Z (RFC3339)
	Notes            string // # Notes = ...
}

// Parse reads a wg-quick configuration from text, including # Key = value comments.
func Parse(content string) (*Config, error) {
	cfg := &Config{}
	var section string // "interface" | "peer"
	var peer *PeerSection
	// Comments immediately preceding the next [Peer] or first field of [Interface].
	pending := map[string]string{}

	flushPeer := func() {
		if peer == nil {
			return
		}
		// Do NOT consume pending here — comments after a peer body belong to the *next* peer.
		cfg.Peers = append(cfg.Peers, *peer)
		peer = nil
	}

	sc := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		// Durable metadata comments: "# Name = foo"
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			body := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(line, "#"), ";"))
			if body == "" {
				continue
			}
			if k, v, ok := strings.Cut(body, "="); ok {
				pending[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
			continue
		}

		lower := strings.ToLower(line)
		if lower == "[interface]" {
			flushPeer()
			section = "interface"
			// Keep pending for interface comments that follow the header.
			continue
		}
		if lower == "[peer]" {
			flushPeer()
			// Comments immediately above [Peer] belong to this peer (Name/Address/…).
			peer = &PeerSection{}
			applyCommentMetaPeer(peer, pending)
			pending = map[string]string{}
			section = "peer"
			continue
		}

		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value", lineNo)
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)

		switch section {
		case "interface":
			// Apply any comments that appeared after [Interface] header once we see fields.
			if len(pending) > 0 {
				applyCommentMetaIface(&cfg.Interface, pending)
				pending = map[string]string{}
			}
			if err := applyInterface(&cfg.Interface, key, val); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "peer":
			if peer == nil {
				return nil, fmt.Errorf("line %d: peer field outside [Peer]", lineNo)
			}
			// Comments right above [Peer] already in pending; apply on first field.
			if len(pending) > 0 {
				applyCommentMetaPeer(peer, pending)
				pending = map[string]string{}
			}
			if err := applyPeer(peer, key, val); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		default:
			return nil, fmt.Errorf("line %d: key outside section", lineNo)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if section == "interface" && len(pending) > 0 {
		applyCommentMetaIface(&cfg.Interface, pending)
	}
	flushPeer()
	// PrivateKey may be empty when conf is incomplete; callers that need it check.
	return cfg, nil
}

func applyCommentMetaIface(iface *InterfaceSection, m map[string]string) {
	if v, ok := m["publickey"]; ok {
		iface.PublicKeyComment = v
	}
	if v, ok := m["peerdns"]; ok {
		iface.PeerDNS = v
	}
	if v, ok := m["peerendpoint"]; ok {
		iface.PeerEndpoint = v
	}
	if v, ok := m["backend"]; ok {
		iface.Backend = v
	}
	if v, ok := m["protocol"]; ok {
		iface.Protocol = v
	}
	if v, ok := m["pairname"]; ok {
		iface.PairName = v
	}
}

func applyCommentMetaPeer(peer *PeerSection, m map[string]string) {
	if v, ok := m["name"]; ok {
		peer.Name = v
	}
	if v, ok := m["address"]; ok {
		peer.Address = v
	}
	if v, ok := m["dns"]; ok {
		peer.DNS = v
	}
	if v, ok := m["clientallowedips"]; ok {
		peer.ClientAllowedIPs = v
	}
	if v, ok := m["notes"]; ok {
		peer.Notes = v
	}
	if v, ok := m["trafficlimit"]; ok {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			peer.TrafficLimit = n
		}
	}
	if v, ok := m["expiresat"]; ok {
		peer.ExpiresAt = v
	}
}

func applyInterface(iface *InterfaceSection, key, val string) error {
	switch strings.ToLower(key) {
	case "privatekey":
		iface.PrivateKey = val
	case "address":
		iface.Address = append(iface.Address, splitCSV(val)...)
	case "listenport":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.ListenPort = n
	case "dns":
		iface.DNS = append(iface.DNS, splitCSV(val)...)
	case "mtu":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.MTU = n
	case "table":
		iface.Table = val
	case "fwmark":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.FwMark = n
	case "preup":
		iface.PreUp = joinHook(iface.PreUp, val)
	case "postup":
		iface.PostUp = joinHook(iface.PostUp, val)
	case "predown":
		iface.PreDown = joinHook(iface.PreDown, val)
	case "postdown":
		iface.PostDown = joinHook(iface.PostDown, val)
	case "saveconfig":
		iface.SaveConfig = strings.EqualFold(val, "true")
	case "jc":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.Jc = n
	case "jmin":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.Jmin = n
	case "jmax":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.Jmax = n
	case "s1":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.S1 = n
	case "s2":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.S2 = n
	case "s3":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.S3 = n
	case "s4":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		iface.S4 = n
	case "h1":
		iface.H1 = val
	case "h2":
		iface.H2 = val
	case "h3":
		iface.H3 = val
	case "h4":
		iface.H4 = val
	case "i1":
		iface.I1 = val
	case "i2":
		iface.I2 = val
	case "i3":
		iface.I3 = val
	case "i4":
		iface.I4 = val
	case "i5":
		iface.I5 = val
	default:
		// Ignore unknown keys for forward compatibility.
	}
	return nil
}

// HasAmnezia reports whether any Amnezia field is set on the interface section.
func (i InterfaceSection) HasAmnezia() bool {
	return i.Jc != 0 || i.Jmin != 0 || i.Jmax != 0 ||
		i.S1 != 0 || i.S2 != 0 || i.S3 != 0 || i.S4 != 0 ||
		i.H1 != "" || i.H2 != "" || i.H3 != "" || i.H4 != "" ||
		i.I1 != "" || i.I2 != "" || i.I3 != "" || i.I4 != "" || i.I5 != ""
}

func joinHook(prev, next string) string {
	if prev == "" {
		return next
	}
	return prev + "\n" + next
}

func applyPeer(peer *PeerSection, key, val string) error {
	switch strings.ToLower(key) {
	case "publickey":
		peer.PublicKey = val
	case "presharedkey":
		peer.PresharedKey = val
	case "allowedips":
		peer.AllowedIPs = append(peer.AllowedIPs, splitCSV(val)...)
	case "endpoint":
		peer.Endpoint = val
	case "persistentkeepalive":
		n, err := parseInt(val)
		if err != nil {
			return err
		}
		peer.PersistentKeepalive = n
	default:
	}
	return nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInt(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q", s)
	}
	return n, nil
}
