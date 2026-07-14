package wgbackend

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

func (b *HostBackend) linkExists(ctx context.Context, name string) bool {
	_, err := b.runner.Run(ctx, "ip", "link", "show", "dev", name)
	return err == nil
}

func (b *HostBackend) linkIsUp(ctx context.Context, name string) bool {
	out, err := b.runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
	if err != nil {
		return false
	}
	// e.g. "2: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> ..."
	return strings.Contains(out, ",UP") || strings.Contains(out, "<UP")
}

func (b *HostBackend) linkMTU(ctx context.Context, name string) int {
	out, err := b.runner.Run(ctx, "ip", "-o", "link", "show", "dev", name)
	if err != nil {
		return 0
	}
	fields := strings.Fields(out)
	for i := 0; i < len(fields)-1; i++ {
		if fields[i] == "mtu" {
			n, _ := strconv.Atoi(fields[i+1])
			return n
		}
	}
	return 0
}

func (b *HostBackend) createLink(ctx context.Context, name string) error {
	if b.linkExists(ctx, name) {
		return nil
	}
	// Prefer ip link add type wireguard
	if _, err := b.runner.Run(ctx, "ip", "link", "add", "dev", name, "type", "wireguard"); err != nil {
		// Fallback: wg-quick style via wireguard-go is not attempted; surface error.
		return err
	}
	return nil
}

func (b *HostBackend) deleteLink(ctx context.Context, name string) error {
	if !b.linkExists(ctx, name) {
		return nil
	}
	_, err := b.runner.Run(ctx, "ip", "link", "del", "dev", name)
	return err
}

func (b *HostBackend) setLinkUp(ctx context.Context, name string, up bool) error {
	state := "down"
	if up {
		state = "up"
	}
	_, err := b.runner.Run(ctx, "ip", "link", "set", "dev", name, state)
	return err
}

func (b *HostBackend) setMTU(ctx context.Context, name string, mtu int) error {
	if mtu <= 0 {
		return nil
	}
	_, err := b.runner.Run(ctx, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(mtu))
	return err
}

func (b *HostBackend) listAddresses(ctx context.Context, name string) ([]string, error) {
	out, err := b.runner.Run(ctx, "ip", "-o", "addr", "show", "dev", name)
	if err != nil {
		return nil, err
	}
	var addrs []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// format: idx: name inet ADDR/PLEN ...
		fields := strings.Fields(line)
		for i := 0; i < len(fields)-1; i++ {
			if fields[i] == "inet" || fields[i] == "inet6" {
				addrs = append(addrs, fields[i+1])
			}
		}
	}
	return addrs, nil
}

func (b *HostBackend) syncAddresses(ctx context.Context, name string, desired []string) error {
	// Nil/empty desired = do not manage addresses (critical for adopt-without-break).
	if len(desired) == 0 {
		return nil
	}
	current, err := b.listAddresses(ctx, name)
	if err != nil {
		// Interface may be brand new.
		current = nil
	}
	want := map[string]struct{}{}
	for _, a := range desired {
		want[a] = struct{}{}
	}
	have := map[string]struct{}{}
	for _, a := range current {
		// skip link-local v6
		if strings.HasPrefix(a, "fe80:") {
			continue
		}
		have[a] = struct{}{}
		if _, ok := want[a]; !ok {
			_, _ = b.runner.Run(ctx, "ip", "addr", "del", a, "dev", name)
		}
	}
	for _, a := range desired {
		if _, ok := have[a]; !ok {
			if _, err := b.runner.Run(ctx, "ip", "addr", "add", a, "dev", name); err != nil {
				// Ignore "File exists"
				if !strings.Contains(err.Error(), "File exists") {
					return fmt.Errorf("addr add %s: %w", a, err)
				}
			}
		}
	}
	return nil
}
