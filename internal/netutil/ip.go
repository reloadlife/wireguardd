package netutil

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// ValidateCIDR checks a single CIDR (e.g. 10.0.0.1/24 or fd00::1/64).
func ValidateCIDR(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty CIDR")
	}
	ip, ipnet, err := net.ParseCIDR(s)
	if err != nil {
		return fmt.Errorf("invalid CIDR %q: %w", s, err)
	}
	if ip == nil || ipnet == nil {
		return fmt.Errorf("invalid CIDR %q", s)
	}
	return nil
}

// ValidateIP accepts a bare IP (no mask).
func ValidateIP(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty IP")
	}
	if net.ParseIP(s) == nil {
		return fmt.Errorf("invalid IP %q", s)
	}
	return nil
}

// ValidateIPOrCIDR accepts "10.0.0.2", "10.0.0.2/32", or "fd00::2/128".
func ValidateIPOrCIDR(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("empty address")
	}
	if strings.Contains(s, "/") {
		return ValidateCIDR(s)
	}
	return ValidateIP(s)
}

// ValidateCIDRList validates a list of CIDRs (interface addresses, AllowedIPs).
func ValidateCIDRList(list []string) error {
	for _, a := range list {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if err := ValidateCIDR(a); err != nil {
			return err
		}
	}
	return nil
}

// ValidateIPOrCIDRList validates assigned/allowed style mixed lists.
func ValidateIPOrCIDRList(list []string) error {
	for _, a := range list {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if err := ValidateIPOrCIDR(a); err != nil {
			return err
		}
	}
	return nil
}

// ValidateEndpoint checks host:port (hostname or IP). Empty is OK.
func ValidateEndpoint(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		// try adding brackets for bare IPv6 without port
		return fmt.Errorf("endpoint must be host:port (got %q)", s)
	}
	if host == "" || port == "" {
		return fmt.Errorf("endpoint must be host:port")
	}
	if _, err := net.LookupPort("udp", port); err != nil {
		return fmt.Errorf("invalid endpoint port %q", port)
	}
	return nil
}

// NormalizeHostIP turns bare IP or host CIDR into a host address string (no mask).
func NormalizeHostIP(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fmt.Errorf("empty")
	}
	if strings.Contains(s, "/") {
		ip, _, err := net.ParseCIDR(s)
		if err != nil {
			return "", err
		}
		// Use the IP part as host identity even if the mask is not host-sized.
		return ip.String(), nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", s)
	}
	return ip.String(), nil
}

// HostCIDR returns host-sized CIDR for an IP (/32 or /128).
func HostCIDR(ipStr string) (string, error) {
	ip := net.ParseIP(strings.TrimSpace(ipStr))
	if ip == nil {
		return "", fmt.Errorf("invalid IP %q", ipStr)
	}
	if ip.To4() != nil {
		return ip.String() + "/32", nil
	}
	return ip.String() + "/128", nil
}

// CollectUsedHosts gathers used host IPs from interface addrs + peer assigned/allowed.
func CollectUsedHosts(ifaceAddrs []string, peerAssigned [][]string, peerAllowed [][]string) map[string]struct{} {
	used := map[string]struct{}{}
	add := func(s string) {
		if h, err := NormalizeHostIP(s); err == nil {
			used[h] = struct{}{}
		}
	}
	for _, a := range ifaceAddrs {
		add(a)
	}
	for _, list := range peerAssigned {
		for _, a := range list {
			add(a)
		}
	}
	for _, list := range peerAllowed {
		for _, a := range list {
			// only host routes count as "used" for allocation
			if strings.HasSuffix(a, "/32") || strings.HasSuffix(a, "/128") || !strings.Contains(a, "/") {
				add(a)
			}
		}
	}
	return used
}

// AllocateNextHost picks the next free host address in the first usable interface subnet.
// Returns assigned bare IP and AllowedIPs host CIDR (/32|/128).
// Skips network/broadcast for IPv4 and interface's own address.
func AllocateNextHost(ifaceAddrs []string, used map[string]struct{}) (assigned string, allowedCIDR string, err error) {
	if used == nil {
		used = map[string]struct{}{}
	}
	type cand struct {
		ip    net.IP
		ipnet *net.IPNet
	}
	var subnets []cand
	for _, a := range ifaceAddrs {
		a = strings.TrimSpace(a)
		if a == "" || strings.HasPrefix(a, "fe80:") {
			continue
		}
		if !strings.Contains(a, "/") {
			// bare IP — assume /24 for v4, /64 for v6 for allocation purposes
			ip := net.ParseIP(a)
			if ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil {
				a = ip.String() + "/24"
			} else {
				a = ip.String() + "/64"
			}
		}
		ip, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		// mark iface IP used
		used[ip.String()] = struct{}{}
		subnets = append(subnets, cand{ip: ip, ipnet: ipnet})
	}
	if len(subnets) == 0 {
		return "", "", fmt.Errorf("no interface addresses to allocate from (set Address= on the interface first)")
	}

	// Prefer IPv4 pool first
	sort.SliceStable(subnets, func(i, j int) bool {
		a4 := subnets[i].ip.To4() != nil
		b4 := subnets[j].ip.To4() != nil
		if a4 != b4 {
			return a4
		}
		return false
	})

	for _, sn := range subnets {
		ones, bits := sn.ipnet.Mask.Size()
		// Only allocate inside reasonably sized pools
		if bits == 32 {
			if ones > 30 {
				continue // /31 /32 too small
			}
			// iterate hosts
			ip := make(net.IP, len(sn.ipnet.IP.To4()))
			copy(ip, sn.ipnet.IP.To4())
			// start after network
			incIP(ip)
			// last is broadcast — stop before
			broadcast := lastIPv4(sn.ipnet)
			for !ip.Equal(broadcast) {
				if sn.ipnet.Contains(ip) {
					s := ip.String()
					if _, ok := used[s]; !ok {
						return s, s + "/32", nil
					}
				}
				incIP(ip)
			}
		} else if bits == 128 {
			if ones > 126 {
				continue
			}
			ip := make(net.IP, len(sn.ipnet.IP.To16()))
			copy(ip, sn.ipnet.IP.To16())
			// start at network+1
			incIP(ip)
			// scan a limited range for practicality
			for i := 0; i < 4096; i++ {
				if sn.ipnet.Contains(ip) {
					s := ip.String()
					if _, ok := used[s]; !ok {
						return s, s + "/128", nil
					}
				}
				incIP(ip)
			}
		}
	}
	return "", "", fmt.Errorf("no free host IP left in interface subnets")
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func lastIPv4(n *net.IPNet) net.IP {
	ip := make(net.IP, 4)
	copy(ip, n.IP.To4())
	for i := 0; i < 4; i++ {
		ip[i] |= ^n.Mask[i]
	}
	return ip
}

// IsAutoToken reports whether the user asked for auto-generation.
func IsAutoToken(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "" || s == "auto" || s == "next" || s == "*"
}

// ParseCSVAddresses splits and trims a CSV of addresses.
func ParseCSVAddresses(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
