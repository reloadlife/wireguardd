package netutil

import "strings"

// ReservedHostInterface reports names that wireguardd must never own.
//
// mesh0 (and mesh*) is the networkingd control-plane overlay managed under
// /etc/wg-mesh by wg-mesh0.service. If wireguardd adopts or recreates it, peer
// public keys silently diverge and the node vanishes from the master while SSH
// and product daemons stay healthy — the 2026-07-19 / 2026-07-23 AMS outages.
func ReservedHostInterface(name string) bool {
	n := strings.TrimSpace(name)
	if n == "" {
		return false
	}
	if n == "mesh0" {
		return true
	}
	// Future control-plane overlays: mesh1, mesh-cp, …
	return strings.HasPrefix(n, "mesh")
}

// ReservedHostInterfaceMessage is the stable API error body for reserved names.
func ReservedHostInterfaceMessage(name string) string {
	return "interface " + name + " is host-managed control-plane mesh " +
		"( /etc/wg-mesh ); wireguardd must not create, adopt, or delete it"
}
