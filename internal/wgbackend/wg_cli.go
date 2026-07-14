package wgbackend

import (
	"context"
)

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
