package confparse

import (
	"fmt"
	"strings"
)

// Render produces a wg-quick compatible configuration.
func Render(cfg *Config) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	if cfg.Interface.PrivateKey != "" {
		fmt.Fprintf(&b, "PrivateKey = %s\n", cfg.Interface.PrivateKey)
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
	if cfg.Interface.PreUp != "" {
		fmt.Fprintf(&b, "PreUp = %s\n", cfg.Interface.PreUp)
	}
	if cfg.Interface.PostUp != "" {
		fmt.Fprintf(&b, "PostUp = %s\n", cfg.Interface.PostUp)
	}
	if cfg.Interface.PreDown != "" {
		fmt.Fprintf(&b, "PreDown = %s\n", cfg.Interface.PreDown)
	}
	if cfg.Interface.PostDown != "" {
		fmt.Fprintf(&b, "PostDown = %s\n", cfg.Interface.PostDown)
	}
	if cfg.Interface.SaveConfig {
		b.WriteString("SaveConfig = true\n")
	}

	for _, p := range cfg.Peers {
		b.WriteString("\n[Peer]\n")
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
