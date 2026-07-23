package wgbackend

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// setAmneziaParams applies Amnezia interface-level params via awg CLI or UAPI socket.
func (b *HostBackend) setAmneziaParams(ctx context.Context, iface string, p AmneziaParams) error {
	if p.IsZero() {
		return nil
	}
	if err := p.Validate(); err != nil {
		return err
	}

	// Prefer awg CLI (works for kernel amneziawg + userspace when installed).
	if b.probe != nil && b.probe.binaryExists(ctx, b.awgTool) {
		args := []string{"set", iface}
		add := func(k string, v int) {
			if v != 0 {
				args = append(args, k, fmt.Sprintf("%d", v))
			}
		}
		addStr := func(k, v string) {
			if v != "" {
				args = append(args, k, v)
			}
		}
		add("jc", p.Jc)
		add("jmin", p.Jmin)
		add("jmax", p.Jmax)
		add("s1", p.S1)
		add("s2", p.S2)
		add("s3", p.S3)
		add("s4", p.S4)
		addStr("h1", p.H1)
		addStr("h2", p.H2)
		addStr("h3", p.H3)
		addStr("h4", p.H4)
		addStr("i1", p.I1)
		addStr("i2", p.I2)
		addStr("i3", p.I3)
		addStr("i4", p.I4)
		addStr("i5", p.I5)
		if len(args) > 2 {
			if _, err := b.runner.Run(ctx, b.awgTool, args...); err != nil {
				// Fall through to UAPI
			} else {
				return nil
			}
		}
	}

	// Userspace UAPI (amneziawg-go).
	sock := filepath.Join(UserspaceSockDirAWG, iface+".sock")
	if _, err := os.Stat(sock); err == nil {
		body := strings.Join(p.UAPILines(), "\n") + "\n"
		return writeUAPI(ctx, sock, body)
	}
	// Also try wireguard sock dir (some builds).
	sock = filepath.Join(UserspaceSockDirWG, iface+".sock")
	if _, err := os.Stat(sock); err == nil {
		body := strings.Join(p.UAPILines(), "\n") + "\n"
		return writeUAPI(ctx, sock, body)
	}
	return fmt.Errorf("cannot apply amnezia params on %s: install awg tools or amneziawg-go", iface)
}

// writeUAPI sends a set operation to a WireGuard userspace control socket.
// Protocol: connect unix, write "set=1\n" + body + "\n", read "errno=N\n".
func writeUAPI(ctx context.Context, sockPath, body string) error {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, "unix", sockPath)
	if err != nil {
		return fmt.Errorf("uapi dial %s: %w", sockPath, err)
	}
	defer func() { _ = conn.Close() }()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	payload := "set=1\n" + body + "\n"
	if _, err := conn.Write([]byte(payload)); err != nil {
		return fmt.Errorf("uapi write: %w", err)
	}
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("uapi read: %w", err)
	}
	resp := string(buf[:n])
	if !strings.Contains(resp, "errno=0") {
		return fmt.Errorf("uapi error response: %s", strings.TrimSpace(resp))
	}
	return nil
}

// configureDeviceViaCLI sets private key / listen port / fwmark with wg or awg.
func (b *HostBackend) configureDeviceViaCLI(ctx context.Context, tool, iface string, desired DesiredInterface) error {
	if tool == "" {
		tool = DefaultWGTool
	}
	args := []string{"set", iface}
	if !IsZeroKey(desired.PrivateKey) {
		// wg set accepts private-key as path or uses stdin with /dev/stdin on some builds;
		// use a temp file for portability.
		f, err := os.CreateTemp("", "wgd-key-*")
		if err != nil {
			return err
		}
		path := f.Name()
		defer func() { _ = os.Remove(path) }()
		if _, err := f.WriteString(desired.PrivateKey + "\n"); err != nil {
			_ = f.Close()
			return err
		}
		_ = f.Close()
		_ = os.Chmod(path, 0o600)
		args = append(args, "private-key", path)
	}
	if desired.ListenPort > 0 {
		args = append(args, "listen-port", fmt.Sprintf("%d", desired.ListenPort))
	}
	if desired.FwMark > 0 {
		args = append(args, "fwmark", fmt.Sprintf("%d", desired.FwMark))
	}
	if len(args) == 2 {
		return nil
	}
	_, err := b.runner.Run(ctx, tool, args...)
	return err
}

// applyPeersViaCLI replaces peer set using wg/awg set (no replace-peers flag on CLI
// for bulk; we remove stale peers then set each desired peer).
func (b *HostBackend) applyPeersViaCLI(ctx context.Context, tool, iface string, peers []DesiredPeer) error {
	if tool == "" {
		tool = DefaultWGTool
	}
	// List current peers
	out, err := b.runner.Run(ctx, tool, "show", iface, "peers")
	if err != nil {
		// interface may be empty
		out = ""
	}
	current := map[string]struct{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			current[line] = struct{}{}
		}
	}
	desired := map[string]DesiredPeer{}
	for _, p := range peers {
		desired[p.PublicKey] = p
	}
	// Remove stale
	for pub := range current {
		if _, ok := desired[pub]; !ok {
			_, _ = b.runner.Run(ctx, tool, "set", iface, "peer", pub, "remove")
		}
	}
	// Apply desired
	for _, p := range peers {
		args := []string{"set", iface, "peer", p.PublicKey}
		if p.PresharedKey != "" && !IsZeroKey(p.PresharedKey) {
			f, err := os.CreateTemp("", "wgd-psk-*")
			if err != nil {
				return err
			}
			path := f.Name()
			_, _ = f.WriteString(p.PresharedKey + "\n")
			_ = f.Close()
			_ = os.Chmod(path, 0o600)
			defer func(p string) { _ = os.Remove(p) }(path)
			args = append(args, "preshared-key", path)
		}
		if p.Endpoint != "" {
			args = append(args, "endpoint", p.Endpoint)
		}
		if p.PersistentKeepalive > 0 {
			args = append(args, "persistent-keepalive", fmt.Sprintf("%d", p.PersistentKeepalive))
		}
		if p.Suspended {
			args = append(args, "allowed-ips", "")
		} else if len(p.AllowedIPs) > 0 {
			args = append(args, "allowed-ips", strings.Join(p.AllowedIPs, ","))
		}
		if _, err := b.runner.Run(ctx, tool, args...); err != nil {
			return fmt.Errorf("set peer %s: %w", p.PublicKey[:8], err)
		}
	}
	return nil
}
