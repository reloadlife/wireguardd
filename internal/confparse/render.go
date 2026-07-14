package confparse

import (
	"fmt"
	"strings"
)

// Render produces a wg-quick compatible configuration with durable # comment metadata.
// Comments survive next to peers/interfaces so a corrupted DB can still be recovered
// from /etc/wireguard/*.conf (same style as existing WGDashboard-style confs).
func Render(cfg *Config) string {
	var b strings.Builder
	b.WriteString("# Managed by wireguardd — comment fields are the durable backup of peer/interface metadata.\n")
	b.WriteString("[Interface]\n")
	if cfg.Interface.PrivateKey != "" {
		fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.Interface.PrivateKey)
	}
	if cfg.Interface.PublicKeyComment != "" {
		fmt.Fprintf(&b, "# PublicKey = %s\n", cfg.Interface.PublicKeyComment)
	}
	for _, a := range cfg.Interface.Address {
		fmt.Fprintf(&b, "Address = %s\n", a)
	}
	if cfg.Interface.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", cfg.Interface.ListenPort)
	}
	if len(cfg.Interface.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(cfg.Interface.DNS, ", "))
	}
	if cfg.Interface.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", cfg.Interface.MTU)
	}
	if cfg.Interface.Table != "" {
		fmt.Fprintf(&b, "Table = %s\n", cfg.Interface.Table)
	}
	if cfg.Interface.FwMark > 0 {
		fmt.Fprintf(&b, "FwMark = %d\n", cfg.Interface.FwMark)
	}
	writeHooks(&b, "PreUp", cfg.Interface.PreUp)
	writeHooks(&b, "PostUp", cfg.Interface.PostUp)
	writeHooks(&b, "PreDown", cfg.Interface.PreDown)
	writeHooks(&b, "PostDown", cfg.Interface.PostDown)
	if cfg.Interface.SaveConfig {
		b.WriteString("SaveConfig = true\n")
	}
	if cfg.Interface.PeerDNS != "" {
		fmt.Fprintf(&b, "# PeerDNS = %s\n", cfg.Interface.PeerDNS)
	}
	if cfg.Interface.PeerEndpoint != "" {
		fmt.Fprintf(&b, "# PeerEndpoint = %s\n", cfg.Interface.PeerEndpoint)
	}

	for _, p := range cfg.Peers {
		b.WriteString("\n")
		if p.Name != "" {
			fmt.Fprintf(&b, "# Name = %s\n", p.Name)
		}
		if p.Address != "" {
			fmt.Fprintf(&b, "# Address = %s\n", p.Address)
		}
		if p.DNS != "" {
			fmt.Fprintf(&b, "# DNS = %s\n", p.DNS)
		}
		if p.ClientAllowedIPs != "" {
			fmt.Fprintf(&b, "# ClientAllowedIPs = %s\n", p.ClientAllowedIPs)
		}
		if p.TrafficLimit > 0 {
			fmt.Fprintf(&b, "# TrafficLimit = %d\n", p.TrafficLimit)
		}
		if p.Notes != "" {
			// single-line notes only
			fmt.Fprintf(&b, "# Notes = %s\n", strings.ReplaceAll(p.Notes, "\n", " "))
		}
		b.WriteString("[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
		}
	}
	return b.String()
}

func writeHooks(b *strings.Builder, key, val string) {
	if val == "" {
		return
	}
	for _, line := range strings.Split(val, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fmt.Fprintf(b, "%s = %s\n", key, line)
	}
}
