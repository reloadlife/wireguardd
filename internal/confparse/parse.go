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

	// Comment metadata (persisted as # Key = value above the section body).
	PublicKeyComment string // # PublicKey = ...
	PeerDNS          string // # PeerDNS = ... (default client DNS)
	PeerEndpoint     string // # PeerEndpoint = ... (public endpoint for clients)
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
	default:
		// Ignore unknown keys for forward compatibility.
	}
	return nil
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
