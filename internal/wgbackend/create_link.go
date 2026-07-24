package wgbackend

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// ensureLink creates the network interface for the given resolved backend if missing.
// If the link exists but the kind is wrong (e.g. stock wireguard where amneziawg
// is required), it is recreated. Peers are re-applied by the reconciler.
// Never touches a correctly-kinded plain WireGuard interface.
func (b *HostBackend) ensureLink(ctx context.Context, name, backend string) error {
	if b.linkExists(ctx, name) {
		kind := b.linkKind(ctx, name)
		wantAmnezia := IsAmneziaBackend(backend)
		gotAmnezia := kind == "amneziawg"
		// Wrong family: recreate under the correct type. Right family → keep.
		if wantAmnezia && !gotAmnezia && kind != "" {
			_ = b.deleteLinkExtended(ctx, name)
		} else if !wantAmnezia && gotAmnezia {
			// Plain WG desired but AWG present — leave (operator may have dual
			// twins). Only create if missing.
			return nil
		} else {
			return nil
		}
	}
	switch backend {
	case BackendKernel:
		return b.createKernelLink(ctx, name, "wireguard")
	case BackendUserspace:
		return b.startUserspace(ctx, name, b.wgGoBin, UserspaceSockDirWG)
	case BackendAmneziaKernel:
		if err := b.createKernelLink(ctx, name, "amneziawg"); err != nil {
			// Fallback to amneziawg-go when kernel module unavailable.
			if b.probe != nil && b.probe.binaryExists(ctx, b.awgGoBin) {
				return b.startUserspace(ctx, name, b.awgGoBin, UserspaceSockDirAWG)
			}
			return err
		}
		return nil
	case BackendAmneziaGo:
		return b.startUserspace(ctx, name, b.awgGoBin, UserspaceSockDirAWG)
	default:
		return fmt.Errorf("unknown backend %q", backend)
	}
}

func (b *HostBackend) createKernelLink(ctx context.Context, name, kind string) error {
	// Best-effort modprobe for amneziawg / wireguard.
	var mod string
	switch kind {
	case "amneziawg":
		mod = ModuleAmneziaWG
	case "wireguard":
		mod = ModuleWireGuard
	default:
		mod = kind
	}
	_, _ = b.runner.Run(ctx, "modprobe", mod)

	if _, err := b.runner.Run(ctx, "ip", "link", "add", "dev", name, "type", kind); err != nil {
		return fmt.Errorf("ip link add type %s: %w", kind, err)
	}
	return nil
}

func (b *HostBackend) startUserspace(ctx context.Context, name, binary, sockDir string) error {
	if binary == "" {
		return fmt.Errorf("userspace binary not configured for %s", name)
	}
	// wireguard-go / amneziawg-go fork to background by default.
	if _, err := b.runner.Run(ctx, binary, name); err != nil {
		return fmt.Errorf("%s %s: %w", binary, name, err)
	}
	// Wait briefly for the link to appear.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if b.linkExists(ctx, name) {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	if b.linkExists(ctx, name) {
		return nil
	}
	return fmt.Errorf("%s started but interface %s did not appear (sock dir %s)", binary, name, sockDir)
}

// deleteLinkExtended removes the interface; for userspace also cleans control sockets.
func (b *HostBackend) deleteLinkExtended(ctx context.Context, name string) error {
	_ = b.deleteLink(ctx, name)
	// Removing the socket also causes userspace go to exit if link del failed.
	for _, dir := range []string{UserspaceSockDirWG, UserspaceSockDirAWG} {
		sock := dir + "/" + name + ".sock"
		_, _ = b.runner.Run(ctx, "rm", "-f", sock)
	}
	return nil
}

// toolForBackend returns wg or awg CLI name for the backend.
func (b *HostBackend) toolForBackend(backend string) string {
	if IsAmneziaBackend(backend) {
		return b.awgTool
	}
	return b.wgTool
}

// linkKind returns the rtnl kind (wireguard / amneziawg) or empty.
func (b *HostBackend) linkKind(ctx context.Context, name string) string {
	out, err := b.runner.Run(ctx, "ip", "-d", "link", "show", "dev", name)
	if err != nil {
		return ""
	}
	low := strings.ToLower(out)
	if strings.Contains(low, "amneziawg") {
		return "amneziawg"
	}
	if strings.Contains(low, "wireguard") {
		return "wireguard"
	}
	return ""
}

// detectLiveBackend best-effort guesses backend of an existing device.
func (b *HostBackend) detectLiveBackend(ctx context.Context, name string) string {
	kind := b.linkKind(ctx, name)
	switch kind {
	case "amneziawg":
		if fileExists(UserspaceSockDirAWG + "/" + name + ".sock") {
			return BackendAmneziaGo
		}
		return BackendAmneziaKernel
	case "wireguard":
		if fileExists(UserspaceSockDirWG + "/" + name + ".sock") {
			return BackendUserspace
		}
		return BackendKernel
	}
	if fileExists(UserspaceSockDirAWG + "/" + name + ".sock") {
		return BackendAmneziaGo
	}
	if fileExists(UserspaceSockDirWG + "/" + name + ".sock") {
		return BackendUserspace
	}
	return BackendKernel
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
