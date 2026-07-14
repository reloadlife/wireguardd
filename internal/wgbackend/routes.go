package wgbackend

import (
	"context"
	"net"
	"strings"
)

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
	ips := peer.AssignedIPs
	if len(ips) == 0 {
		// Fall back to host-sized AllowedIPs
		for _, a := range peer.AllowedIPs {
			ips = append(ips, a)
		}
	}
	for _, ip := range ips {
		if err := b.blackholeCIDR(ctx, ip, suspend); err != nil {
			return err
		}
	}
	return nil
}
