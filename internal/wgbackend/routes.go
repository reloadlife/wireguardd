package wgbackend

import (
	"context"
	"net"
	"strings"
	"time"
)

// blackholeListTTL bounds how stale the listing behind delete decisions can be.
// A route missed in that window is removed by the next reconcile.
const blackholeListTTL = 5 * time.Second

// blackholeRouteMissing reports whether cidr is known to have no blackhole route.
// Reconciles ask this for every unsuspended peer, so forking `ip route del` for
// each of them (hundreds per minute) is what it exists to avoid. Listing failures
// answer false: an unnecessary del is harmless, a skipped one leaves a peer cut off.
func (b *HostBackend) blackholeRouteMissing(ctx context.Context, cidr string) bool {
	if b.blackholes == nil || time.Since(b.blackholesAt) >= blackholeListTTL {
		v4, err4 := b.runner.Run(ctx, "ip", "route", "show", "type", "blackhole")
		v6, err6 := b.runner.Run(ctx, "ip", "-6", "route", "show", "type", "blackhole")
		if err4 != nil || err6 != nil {
			b.blackholes = nil
			return false
		}
		listed := make(map[string]struct{})
		for _, line := range strings.Split(v4+"\n"+v6, "\n") {
			if f := strings.Fields(line); len(f) >= 2 && f[0] == "blackhole" {
				listed[hostRouteKey(f[1])] = struct{}{}
			}
		}
		b.blackholes, b.blackholesAt = listed, time.Now()
	}
	_, present := b.blackholes[hostRouteKey(cidr)]
	return !present
}

// hostRouteKey matches `ip route` output, which omits a host route's prefix length.
func hostRouteKey(cidr string) string {
	return strings.TrimSuffix(strings.TrimSuffix(cidr, "/32"), "/128")
}

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
	} else if b.blackholeRouteMissing(ctx, cidr) {
		return nil
	}
	_, err = b.runner.Run(ctx, "ip", "route", action, "blackhole", cidr)
	if err == nil && b.blackholes != nil {
		if add {
			b.blackholes[hostRouteKey(cidr)] = struct{}{}
		} else {
			delete(b.blackholes, hostRouteKey(cidr))
		}
	}
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
