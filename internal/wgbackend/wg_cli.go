package wgbackend

import (
	"context"
	"fmt"
	"strings"
)

// WgSet applies a minimal wg set command for a single peer (fallback path).
func (b *HostBackend) wgSetPeer(ctx context.Context, iface string, peer DesiredPeer) error {
	args := []string{"set", iface, "peer", peer.PublicKey}
	if peer.PresharedKey != "" {
		args = append(args, "preshared-key", "/dev/stdin")
	}
	if peer.Endpoint != "" {
		args = append(args, "endpoint", peer.Endpoint)
	}
	if peer.PersistentKeepalive > 0 {
		args = append(args, "persistent-keepalive", fmt.Sprintf("%d", peer.PersistentKeepalive))
	}
	allowed := peer.AllowedIPs
	if peer.Suspended {
		allowed = []string{}
	}
	if len(allowed) > 0 {
		args = append(args, "allowed-ips", strings.Join(allowed, ","))
	}
	_, err := b.runner.Run(ctx, "wg", args...)
	return err
}

// WgQuickUp runs wg-quick up for an interface name.
func (b *HostBackend) WgQuickUp(ctx context.Context, name string) error {
	_, err := b.runner.Run(ctx, "wg-quick", "up", name)
	return err
}

// WgQuickDown runs wg-quick down.
func (b *HostBackend) WgQuickDown(ctx context.Context, name string) error {
	_, err := b.runner.Run(ctx, "wg-quick", "down", name)
	return err
}

// WgQuickSave runs wg-quick save.
func (b *HostBackend) WgQuickSave(ctx context.Context, name string) error {
	_, err := b.runner.Run(ctx, "wg-quick", "save", name)
	return err
}
