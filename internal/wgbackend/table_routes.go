package wgbackend

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/advanced-wg/awgctrl-go/wgtypes"
)

// Table mode mirrors wg-quick Table= setting.
//
//	off    — do not install peer AllowedIP routes or policy rules
//	auto   — install routes in the main table; default routes (0.0.0.0/0, ::/0)
//	         use a dedicated table + fwmark + suppress_prefixlength (wg-quick style)
//	number — install all AllowedIP routes in table <TableID> and policy rules
//	         so traffic from the interface addresses looks up that table
//
// Ref: https://git.zx2c4.com/wireguard-tools/tree/src/wg-quick/linux.bash

const (
	tableModeOff    = "off"
	tableModeAuto   = "auto"
	tableModeNumber = "number"

	// Priority band for rules we install (avoid clobbering system lows).
	rulePrioBase = 32764
)

type routeKey struct {
	Dst   string // CIDR
	Table string // "main" or numeric string or "default-special"
	Proto string // "4" or "6"
}

type ruleKey struct {
	Family string // "4" or "6"
	Spec   string // full identity string for comparison
}

type ifaceRouteState struct {
	routes map[routeKey]struct{}
	rules  map[ruleKey]struct{}
	fwmark int
}

type routeState struct {
	mu     sync.Mutex
	ifaces map[string]*ifaceRouteState
}

func newRouteState() *routeState {
	return &routeState{ifaces: make(map[string]*ifaceRouteState)}
}

func (s *routeState) get(name string) *ifaceRouteState {
	st, ok := s.ifaces[name]
	if !ok {
		st = &ifaceRouteState{
			routes: make(map[routeKey]struct{}),
			rules:  make(map[ruleKey]struct{}),
		}
		s.ifaces[name] = st
	}
	return st
}

// SyncRoutes installs/removes AllowedIP routes and policy rules for an interface.
func (b *HostBackend) SyncRoutes(ctx context.Context, desired DesiredInterface) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.routes == nil {
		b.routes = newRouteState()
	}
	// For auto + default routes, ensure device fwmark matches the special table (wg-quick).
	if err := b.ensureDefaultRouteFwMark(ctx, desired); err != nil {
		return err
	}
	return b.routes.sync(ctx, b.runner, desired)
}

func (b *HostBackend) ensureDefaultRouteFwMark(ctx context.Context, desired DesiredInterface) error {
	mode := normalizeTableMode(desired.TableMode)
	if mode != tableModeAuto || !desired.Enabled {
		return nil
	}
	hasDefault := false
	for _, p := range desired.Peers {
		if p.Suspended {
			continue
		}
		for _, a := range p.AllowedIPs {
			if _, isDef, err := classifyCIDR(normalizeCIDR(a)); err == nil && isDef {
				hasDefault = true
				break
			}
		}
	}
	if !hasDefault {
		return nil
	}
	mark := desired.FwMark
	if mark <= 0 {
		if desired.ListenPort > 0 {
			mark = desired.ListenPort
		} else {
			mark = 51820
		}
	}
	if b.client != nil {
		fm := mark
		_ = b.client.ConfigureDevice(ctx, desired.Name, wgtypes.Config{FirewallMark: &fm})
	} else if b.runner != nil {
		_, _ = b.runner.Run(ctx, "wg", "set", desired.Name, "fwmark", strconv.Itoa(mark))
	}
	return nil
}

func normalizeCIDR(a string) string {
	a = strings.TrimSpace(a)
	if a == "" {
		return a
	}
	if strings.Contains(a, "/") {
		return a
	}
	ip := net.ParseIP(a)
	if ip == nil {
		return a
	}
	if ip.To4() != nil {
		return a + "/32"
	}
	return a + "/128"
}

// clearInterfaceRoutes removes managed routes/rules for an interface (best-effort).
func (b *HostBackend) clearInterfaceRoutes(ctx context.Context, name string) {
	if b.routes == nil || b.runner == nil {
		return
	}
	b.routes.mu.Lock()
	defer b.routes.mu.Unlock()
	st := b.routes.ifaces[name]
	if st == nil {
		return
	}
	for rk := range st.routes {
		_ = delRoute(ctx, b.runner, name, rk)
	}
	for rk := range st.rules {
		_ = delRule(ctx, b.runner, rk)
	}
	delete(b.routes.ifaces, name)
}

func (s *routeState) sync(ctx context.Context, runner Runner, desired DesiredInterface) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.get(desired.Name)

	mode := normalizeTableMode(desired.TableMode)
	if mode == tableModeOff || !desired.Enabled {
		// Tear down everything we own.
		for rk := range st.routes {
			_ = delRoute(ctx, runner, desired.Name, rk)
		}
		for rk := range st.rules {
			_ = delRule(ctx, runner, rk)
		}
		st.routes = make(map[routeKey]struct{})
		st.rules = make(map[ruleKey]struct{})
		return nil
	}

	fwmark := desired.FwMark
	if fwmark <= 0 {
		// Match wg-quick: prefer listen port as mark when auto-default handling needs it.
		if desired.ListenPort > 0 {
			fwmark = desired.ListenPort
		} else {
			fwmark = 51820
		}
	}
	st.fwmark = fwmark

	wantRoutes := map[routeKey]struct{}{}
	wantRules := map[ruleKey]struct{}{}

	// Collect AllowedIPs from non-suspended peers.
	var allowed []string
	for _, p := range desired.Peers {
		if p.Suspended {
			continue
		}
		for _, a := range p.AllowedIPs {
			a = strings.TrimSpace(a)
			if a == "" {
				continue
			}
			if !strings.Contains(a, "/") {
				if ip := net.ParseIP(a); ip != nil {
					if ip.To4() != nil {
						a = a + "/32"
					} else {
						a = a + "/128"
					}
				} else {
					continue
				}
			}
			allowed = append(allowed, a)
		}
	}
	sort.Strings(allowed)
	allowed = uniqueStrings(allowed)

	tableNum := 0
	if mode == tableModeNumber && desired.TableID != nil {
		tableNum = *desired.TableID
	}

	for _, cidr := range allowed {
		proto, isDefault, err := classifyCIDR(cidr)
		if err != nil {
			continue
		}
		rk := routeKey{Dst: cidr, Proto: proto}

		switch mode {
		case tableModeAuto:
			if isDefault {
				// Special table = fwmark (wg-quick style)
				rk.Table = strconv.Itoa(fwmark)
				wantRoutes[rk] = struct{}{}
				// Rules for default-route split
				for _, fam := range []string{proto} {
					// not fwmark FWMARK table FWMARK
					wantRules[ruleKey{
						Family: fam,
						Spec:   fmt.Sprintf("not from all fwmark 0x%x lookup %d", fwmark, fwmark),
					}] = struct{}{}
					// table main suppress_prefixlength 0
					wantRules[ruleKey{
						Family: fam,
						Spec:   "from all lookup main suppress_prefixlength 0",
					}] = struct{}{}
				}
			} else {
				rk.Table = "main"
				wantRoutes[rk] = struct{}{}
			}
		case tableModeNumber:
			rk.Table = strconv.Itoa(tableNum)
			wantRoutes[rk] = struct{}{}
		}
	}

	if mode == tableModeNumber && tableNum > 0 {
		// Policy: traffic from each interface address looks up the custom table.
		for _, addr := range desired.Addresses {
			host, fam, err := addrHostFamily(addr)
			if err != nil {
				continue
			}
			wantRules[ruleKey{
				Family: fam,
				Spec:   fmt.Sprintf("from %s lookup %d", host, tableNum),
			}] = struct{}{}
		}
		// Also: packets arriving on the wg iface can use the table (optional but useful).
		for _, fam := range []string{"4", "6"} {
			wantRules[ruleKey{
				Family: fam,
				Spec:   fmt.Sprintf("from all iif %s lookup %d", desired.Name, tableNum),
			}] = struct{}{}
		}
	}

	// Remove stale routes
	for rk := range st.routes {
		if _, ok := wantRoutes[rk]; !ok {
			_ = delRoute(ctx, runner, desired.Name, rk)
			delete(st.routes, rk)
		}
	}
	// Remove stale rules
	for rk := range st.rules {
		if _, ok := wantRules[rk]; !ok {
			_ = delRule(ctx, runner, rk)
			delete(st.rules, rk)
		}
	}

	// Add missing routes
	var errs []string
	for rk := range wantRoutes {
		if _, ok := st.routes[rk]; ok {
			continue
		}
		if err := addRoute(ctx, runner, desired.Name, rk); err != nil {
			// ignore file exists
			if !strings.Contains(err.Error(), "File exists") && !strings.Contains(err.Error(), "exists") {
				errs = append(errs, fmt.Sprintf("route %s: %v", rk.Dst, err))
				continue
			}
		}
		st.routes[rk] = struct{}{}
	}
	// Add missing rules
	prio := rulePrioBase
	for rk := range wantRules {
		if _, ok := st.rules[rk]; ok {
			continue
		}
		if err := addRule(ctx, runner, rk, prio); err != nil {
			if !strings.Contains(err.Error(), "File exists") {
				errs = append(errs, fmt.Sprintf("rule %s: %v", rk.Spec, err))
				continue
			}
		}
		st.rules[rk] = struct{}{}
		prio++
	}

	// For custom tables: ensure fwmark is applied on the device if set
	// (wg uses firewall mark for policy routing with defaults).
	// EnsureInterface already sets FirewallMark via wgctrl when > 0.

	if len(errs) > 0 {
		return fmt.Errorf("sync routes: %s", strings.Join(errs, "; "))
	}
	return nil
}

func normalizeTableMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	switch mode {
	case "", tableModeAuto:
		return tableModeAuto
	case tableModeOff:
		return tableModeOff
	case tableModeNumber, "custom":
		return tableModeNumber
	default:
		// numeric string → number mode
		if _, err := strconv.Atoi(mode); err == nil {
			return tableModeNumber
		}
		// Named custom tables (e.g. "wgvpn", "gaming") are managed via PostUp hooks
		// on the host — do not install/remove routes ourselves.
		return tableModeOff
	}
}

// ResolveTableID returns the effective table id for conf export / number mode.
func ResolveTableID(mode string, id *int) (string, int) {
	mode = normalizeTableMode(mode)
	switch mode {
	case tableModeOff:
		return "off", 0
	case tableModeNumber:
		if id != nil {
			return strconv.Itoa(*id), *id
		}
		return "auto", 0
	default:
		return "auto", 0
	}
}

func classifyCIDR(cidr string) (proto string, isDefault bool, err error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", false, err
	}
	ones, bits := ipnet.Mask.Size()
	isDefault = ones == 0
	if ipnet.IP.To4() != nil {
		return "4", isDefault, nil
	}
	if bits == 128 {
		return "6", isDefault, nil
	}
	return "6", isDefault, nil
}

func addrHostFamily(addr string) (host, fam string, err error) {
	if strings.Contains(addr, "/") {
		ip, _, e := net.ParseCIDR(addr)
		if e != nil {
			return "", "", e
		}
		if ip.To4() != nil {
			return ip.String(), "4", nil
		}
		return ip.String(), "6", nil
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return "", "", fmt.Errorf("bad addr %s", addr)
	}
	if ip.To4() != nil {
		return ip.String(), "4", nil
	}
	return ip.String(), "6", nil
}

func addRoute(ctx context.Context, runner Runner, iface string, rk routeKey) error {
	args := []string{"-" + rk.Proto, "route", "replace", rk.Dst, "dev", iface}
	if rk.Table != "" && rk.Table != "main" {
		args = append(args, "table", rk.Table)
	}
	_, err := runner.Run(ctx, "ip", args...)
	return err
}

func delRoute(ctx context.Context, runner Runner, iface string, rk routeKey) error {
	args := []string{"-" + rk.Proto, "route", "del", rk.Dst, "dev", iface}
	if rk.Table != "" && rk.Table != "main" {
		args = append(args, "table", rk.Table)
	}
	_, err := runner.Run(ctx, "ip", args...)
	if err != nil && (strings.Contains(err.Error(), "No such") || strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "Cannot find")) {
		return nil
	}
	return err
}

func addRule(ctx context.Context, runner Runner, rk ruleKey, prio int) error {
	// Reconstruct ip rule add args from Spec.
	// Spec formats we generate:
	//   not from all fwmark 0xN lookup T
	//   from all lookup main suppress_prefixlength 0
	//   from <ip> lookup T
	//   from all iif <if> lookup T
	args := []string{"-" + rk.Family, "rule", "add"}
	fields := strings.Fields(rk.Spec)
	args = append(args, fields...)
	args = append(args, "priority", strconv.Itoa(prio))
	_, err := runner.Run(ctx, "ip", args...)
	return err
}

func delRule(ctx context.Context, runner Runner, rk ruleKey) error {
	args := []string{"-" + rk.Family, "rule", "del"}
	args = append(args, strings.Fields(rk.Spec)...)
	_, err := runner.Run(ctx, "ip", args...)
	if err != nil && (strings.Contains(err.Error(), "No such") || strings.Contains(err.Error(), "not found")) {
		return nil
	}
	return err
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
