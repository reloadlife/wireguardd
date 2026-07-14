package wgbackend

import (
	"context"
	"fmt"
	"strconv"
	"strings"
)

// applyTCBandwidth installs simple HTB rate limits matched by destination IP.
// Best-effort: failures are returned to the caller to log.
func (b *HostBackend) applyTCBandwidth(ctx context.Context, iface string, peer DesiredPeer) error {
	if b.bandwidthBackend == "none" || b.bandwidthBackend == "" {
		return nil
	}
	if peer.BandwidthRxBps <= 0 && peer.BandwidthTxBps <= 0 {
		return nil
	}
	// Ensure root qdisc exists (idempotent best-effort).
	_, _ = b.runner.Run(ctx, "tc", "qdisc", "add", "dev", iface, "root", "handle", "1:", "htb", "default", "30")

	ips := peer.AssignedIPs
	if len(ips) == 0 {
		for _, a := range peer.AllowedIPs {
			// only use /32 or /128
			if strings.HasSuffix(a, "/32") || strings.HasSuffix(a, "/128") {
				ips = append(ips, strings.Split(a, "/")[0])
			}
		}
	}
	for i, ip := range ips {
		ip = strings.Split(ip, "/")[0]
		classID := fmt.Sprintf("1:%d", 10+i)
		rate := peer.BandwidthTxBps
		if rate <= 0 {
			rate = peer.BandwidthRxBps
		}
		if rate <= 0 {
			continue
		}
		// rate in bit/s for tc
		_, err := b.runner.Run(ctx, "tc", "class", "replace", "dev", iface, "parent", "1:", "classid", classID,
			"htb", "rate", strconv.FormatInt(rate, 10)+"bit", "ceil", strconv.FormatInt(rate, 10)+"bit")
		if err != nil {
			return err
		}
		// Match destination (egress to peer tunnel IP)
		_, _ = b.runner.Run(ctx, "tc", "filter", "replace", "dev", iface, "protocol", "ip", "parent", "1:",
			"prio", "1", "u32", "match", "ip", "dst", ip, "flowid", classID)
	}
	return nil
}
