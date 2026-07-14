package wgbackend

import (
	"context"
	"net"
	"strings"
)

// ensure strings is used for hostSizedIPs

// blackholeCIDR installs or removes a blackhole route for a host/CIDR.
func (b *HostBackend) blackholeCIDR(ctx context.Context, cidr string, add bool) error {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		// try as bare IP
		ip = net.ParseIP(cidr)
		if ip == nil {
			return nil
		}
		if ip.To4() != nil {
			cidr = ip.String() + "/32"
		} else {
			cidr = ip.String() + "/128"
		}
		_, ipnet, err = net.ParseCIDR(cidr)
		if err != nil {
			return err
		}
	}
	_ = ip
	_ = ipnet
	action := "del"
	if add {
		action = "replace"
	}
	_, err = b.runner.Run(ctx, "ip", "route", action, "blackhole", cidr)
	if err != nil && !add && strings.Contains(err.Error(), "No such process") {
		return nil
	}
	// also ignore missing on del
	if err != nil && !add {
		return nil
	}
	return err
}

func (b *HostBackend) applySuspendRoutes(ctx context.Context, peer DesiredPeer, suspend bool) error {
	// Only blackhole host-sized destinations. Never blackhole 0.0.0.0/0 or large prefixes.
	ips := hostSizedIPs(peer.AssignedIPs)
	if len(ips) == 0 {
		ips = hostSizedIPs(peer.AllowedIPs)
	}
	for _, ip := range ips {
		if err := b.blackholeCIDR(ctx, ip, suspend); err != nil {
			return err
		}
	}
	return nil
}

func hostSizedIPs(cidrs []string) []string {
	var out []string
	for _, a := range cidrs {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if !strings.Contains(a, "/") {
			out = append(out, a)
			continue
		}
		if strings.HasSuffix(a, "/32") || strings.HasSuffix(a, "/128") {
			out = append(out, a)
		}
		// skip broader prefixes (would blackhole LAN/default routes)
	}
	return out
}
