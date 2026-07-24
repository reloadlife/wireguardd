package wgbackend

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// deviceFromCLI reads live interface + peer state via `awg`/`wg` show dump.
//
// Primary path is awgctrl netlink (github.com/advanced-wg/awgctrl-go). This CLI
// path is the fallback when genl is unavailable (missing CAP_NET_ADMIN on the
// Amnezia family, userspace socket only, broken module). Without handshake
// counters, wireguardd reports connected=false forever, the control plane never
// upserts live ConnectionSessions for AWG clients, and hourly + $/GB billing
// silently skips them.
//
// dump format (wg(8) / awg show <iface> dump), tab-separated:
//
//	iface: private-key  public-key  listen-port  fwmark
//	peer:  public-key  psk  endpoint  allowed-ips  latest-handshake  rx  tx  keepalive
func (b *HostBackend) deviceFromCLI(ctx context.Context, name string) (*Device, error) {
	kind := b.linkKind(ctx, name)
	tools := b.dumpToolsForKind(kind)
	var lastErr error
	for _, tool := range tools {
		out, err := b.runner.Run(ctx, tool, "show", name, "dump")
		if err != nil {
			lastErr = err
			continue
		}
		dev, err := parseShowDump(name, out)
		if err != nil {
			lastErr = err
			continue
		}
		return &dev, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no dump tool available for %s", name)
}

// dumpToolsForKind returns preferred CLI tools for reading dump output.
func (b *HostBackend) dumpToolsForKind(kind string) []string {
	awg := b.awgTool
	if awg == "" {
		awg = DefaultAWGTool
	}
	wg := b.wgTool
	if wg == "" {
		wg = DefaultWGTool
	}
	if kind == "amneziawg" {
		return []string{awg, wg}
	}
	// Plain wireguard: try wg first, awg second (awg often understands both).
	return []string{wg, awg}
}

// parseShowDump converts `wg/awg show <iface> dump` text into a Device.
func parseShowDump(name, raw string) (Device, error) {
	lines := strings.Split(strings.TrimSpace(raw), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return Device{}, fmt.Errorf("empty dump for %s", name)
	}
	ifaceFields := strings.Split(lines[0], "\t")
	if len(ifaceFields) < 4 {
		// Some builds space-separate; tolerate either.
		ifaceFields = strings.Fields(lines[0])
	}
	if len(ifaceFields) < 4 {
		return Device{}, fmt.Errorf("malformed dump header for %s: %q", name, lines[0])
	}
	port, _ := strconv.Atoi(ifaceFields[2])
	fwmark := 0
	if ifaceFields[3] != "off" {
		fwmark, _ = strconv.Atoi(ifaceFields[3])
	}
	priv := ifaceFields[0]
	if IsZeroKey(priv) || priv == "(none)" {
		priv = ""
	}
	pub := ifaceFields[1]
	if IsZeroKey(pub) || pub == "(none)" {
		pub = ""
	}
	dev := Device{
		Name:         name,
		PrivateKey:   priv,
		PublicKey:    pub,
		ListenPort:   port,
		FirewallMark: fwmark,
		Up:           true,
	}
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 8 {
			// Fall back to whitespace for odd tools; allowed-ips may break this.
			f = strings.Fields(line)
		}
		if len(f) < 8 {
			continue
		}
		peerPub := f[0]
		if peerPub == "" || IsZeroKey(peerPub) {
			continue
		}
		psk := f[1]
		if IsZeroKey(psk) || psk == "(none)" {
			psk = ""
		}
		endpoint := f[2]
		if endpoint == "(none)" {
			endpoint = ""
		}
		var allowed []string
		if f[3] != "" && f[3] != "(none)" {
			for _, a := range strings.Split(f[3], ",") {
				a = strings.TrimSpace(a)
				if a != "" {
					allowed = append(allowed, a)
				}
			}
		}
		var hs time.Time
		if sec, err := strconv.ParseInt(f[4], 10, 64); err == nil && sec > 0 {
			hs = time.Unix(sec, 0)
		}
		rx, _ := strconv.ParseInt(f[5], 10, 64)
		tx, _ := strconv.ParseInt(f[6], 10, 64)
		var ka time.Duration
		if n, err := strconv.Atoi(f[7]); err == nil && n > 0 {
			ka = time.Duration(n) * time.Second
		}
		dev.Peers = append(dev.Peers, Peer{
			PublicKey:                   peerPub,
			PresharedKey:                psk,
			Endpoint:                    endpoint,
			AllowedIPs:                  allowed,
			PersistentKeepaliveInterval: ka,
			LastHandshakeTime:           hs,
			ReceiveBytes:                rx,
			TransmitBytes:               tx,
		})
	}
	return dev, nil
}
