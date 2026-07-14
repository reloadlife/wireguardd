package confparse

import (
	"bufio"
	"fmt"
	"strings"
)

// Config is a parsed wg-quick style configuration.
type Config struct {
	Interface InterfaceSection
	Peers     []PeerSection
}

// InterfaceSection holds [Interface] fields.
type InterfaceSection struct {
	PrivateKey string
	Address    []string
	ListenPort int
	DNS        []string
	MTU        int
	Table      string // "off", "auto", or number as string
	FwMark     int
	PreUp      string
	PostUp     string
	PreDown    string
	PostDown   string
	SaveConfig bool
}

// PeerSection holds [Peer] fields.
type PeerSection struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive int
}

// Parse reads a wg-quick configuration from text.
func Parse(content string) (*Config, error) {
	cfg := &Config{}
	var section string // "interface" | "peer"
	var peer *PeerSection

	sc := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		lower := strings.ToLower(line)
		if lower == "[interface]" {
			if peer != nil {
				cfg.Peers = append(cfg.Peers, *peer)
				peer = nil
			}
			section = "interface"
			continue
		}
		if lower == "[peer]" {
			if peer != nil {
				cfg.Peers = append(cfg.Peers, *peer)
			}
			peer = &PeerSection{}
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
			if err := applyInterface(&cfg.Interface, key, val); err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}
		case "peer":
			if peer == nil {
				return nil, fmt.Errorf("line %d: peer field outside [Peer]", lineNo)
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
	if peer != nil {
		cfg.Peers = append(cfg.Peers, *peer)
	}
	if cfg.Interface.PrivateKey == "" {
		return nil, fmt.Errorf("missing Interface.PrivateKey")
	}
	return cfg, nil
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
		iface.PreUp = val
	case "postup":
		iface.PostUp = val
	case "predown":
		iface.PreDown = val
	case "postdown":
		iface.PostDown = val
	case "saveconfig":
		iface.SaveConfig = strings.EqualFold(val, "true")
	default:
		// Ignore unknown keys for forward compatibility.
	}
	return nil
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
	var n int
	_, err := fmt.Sscanf(s, "%d", &n)
	if err != nil {
		return 0, fmt.Errorf("invalid integer %q", s)
	}
	return n, nil
}
