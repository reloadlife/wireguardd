package wgbackend

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Backend kinds supported by HostBackend.
// Prefer kernel when available; fall back to userspace implementations.
const (
	BackendAuto          = "auto"
	BackendKernel        = "kernel"         // stock wireguard.ko  (ip link type wireguard)
	BackendUserspace     = "userspace"      // wireguard-go
	BackendAmneziaKernel = "amnezia_kernel" // amneziawg.ko       (ip link type amneziawg)
	BackendAmneziaGo     = "amnezia_go"     // amneziawg-go
)

// Protocol flavors.
const (
	ProtocolWG  = "wg"  // plain WireGuard
	ProtocolAWG = "awg" // AmneziaWG (obfuscated)
)

// AmneziaParams are interface-level AmneziaWG obfuscation parameters.
// S* and H* must match on both ends; Jc/Jmin/Jmax may differ (often client-only).
// Empty / zero values mean "unset" (AWG treats unset as 0; H defaults to 1..4).
type AmneziaParams struct {
	Jc   int    `json:"jc,omitempty"`
	Jmin int    `json:"jmin,omitempty"`
	Jmax int    `json:"jmax,omitempty"`
	S1   int    `json:"s1,omitempty"`
	S2   int    `json:"s2,omitempty"`
	S3   int    `json:"s3,omitempty"`
	S4   int    `json:"s4,omitempty"`
	H1   string `json:"h1,omitempty"`
	H2   string `json:"h2,omitempty"`
	H3   string `json:"h3,omitempty"`
	H4   string `json:"h4,omitempty"`
	I1   string `json:"i1,omitempty"`
	I2   string `json:"i2,omitempty"`
	I3   string `json:"i3,omitempty"`
	I4   string `json:"i4,omitempty"`
	I5   string `json:"i5,omitempty"`
}

// IsZero reports whether no Amnezia fields are set.
func (p AmneziaParams) IsZero() bool {
	return p.Jc == 0 && p.Jmin == 0 && p.Jmax == 0 &&
		p.S1 == 0 && p.S2 == 0 && p.S3 == 0 && p.S4 == 0 &&
		p.H1 == "" && p.H2 == "" && p.H3 == "" && p.H4 == "" &&
		p.I1 == "" && p.I2 == "" && p.I3 == "" && p.I4 == "" && p.I5 == ""
}

// Neutral returns Amnezia params that are wire-compatible with plain WireGuard
// (stock headers, no padding). Useful for dual-compat AWG interfaces.
func NeutralAmneziaParams() AmneziaParams {
	return AmneziaParams{H1: "1", H2: "2", H3: "3", H4: "4"}
}

// IsNeutral reports stock WireGuard-compatible H/S (junk may still be non-zero).
func (p AmneziaParams) IsNeutral() bool {
	h1, h2, h3, h4 := p.H1, p.H2, p.H3, p.H4
	if h1 == "" {
		h1 = "1"
	}
	if h2 == "" {
		h2 = "2"
	}
	if h3 == "" {
		h3 = "3"
	}
	if h4 == "" {
		h4 = "4"
	}
	return h1 == "1" && h2 == "2" && h3 == "3" && h4 == "4" &&
		p.S1 == 0 && p.S2 == 0 && p.S3 == 0 && p.S4 == 0
}

// NormalizeBackend returns a canonical backend string or error.
func NormalizeBackend(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return BackendAuto, nil
	}
	switch s {
	case BackendAuto, BackendKernel, BackendUserspace, BackendAmneziaKernel, BackendAmneziaGo:
		return s, nil
	// Friendly aliases
	case "wg", "wireguard", "wireguard-kernel":
		return BackendKernel, nil
	case "wireguard-go", "wg-go", "go":
		return BackendUserspace, nil
	case "amnezia", "amneziawg", "awg", "amnezia-kernel", "amneziawg-kernel":
		return BackendAmneziaKernel, nil
	case "amnezia-go", "amneziawg-go", "awg-go":
		return BackendAmneziaGo, nil
	default:
		return "", fmt.Errorf("invalid backend %q (want auto|kernel|userspace|amnezia_kernel|amnezia_go)", s)
	}
}

// NormalizeProtocol returns wg|awg.
func NormalizeProtocol(s string) (string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ProtocolWG, nil
	}
	switch s {
	case ProtocolWG, "wireguard", "plain":
		return ProtocolWG, nil
	case ProtocolAWG, "amnezia", "amneziawg":
		return ProtocolAWG, nil
	default:
		return "", fmt.Errorf("invalid protocol %q (want wg|awg)", s)
	}
}

// IsAmneziaBackend reports whether backend speaks AmneziaWG.
func IsAmneziaBackend(backend string) bool {
	b, _ := NormalizeBackend(backend)
	return b == BackendAmneziaKernel || b == BackendAmneziaGo
}

// IsUserspaceBackend reports go implementations.
func IsUserspaceBackend(backend string) bool {
	b, _ := NormalizeBackend(backend)
	return b == BackendUserspace || b == BackendAmneziaGo
}

// DefaultNoisePreset generates a non-neutral Amnezia param set suitable for DPI evasion.
// H values are unique random uint32s in [5, 2^31); S1/S2 in recommended ranges.
// Jc is left 0 on the server (clients may set their own junk).
func DefaultNoisePreset() AmneziaParams {
	h := func() string {
		var b [4]byte
		_, _ = rand.Read(b[:])
		// 5 .. 2^31-1
		v := binary.BigEndian.Uint32(b[:])%0x7ffffffb + 5
		return strconv.FormatUint(uint64(v), 10)
	}
	// Ensure uniqueness of H1–H4
	seen := map[string]struct{}{}
	uniq := func() string {
		for {
			v := h()
			if _, ok := seen[v]; !ok {
				seen[v] = struct{}{}
				return v
			}
		}
	}
	s1 := 15 + int(randByte()%136) // 15–150
	s2 := 15 + int(randByte()%136)
	// Constraint from Amnezia docs: S1 + 56 ≠ S2
	for s1+56 == s2 {
		s2 = 15 + int(randByte()%136)
	}
	return AmneziaParams{
		S1: s1,
		S2: s2,
		H1: uniq(),
		H2: uniq(),
		H3: uniq(),
		H4: uniq(),
	}
}

func randByte() byte {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}

// UAPILines returns amnezia keys for the WireGuard configuration protocol.
func (p AmneziaParams) UAPILines() []string {
	var lines []string
	addInt := func(k string, v int) {
		if v != 0 {
			lines = append(lines, fmt.Sprintf("%s=%d", k, v))
		}
	}
	addStr := func(k, v string) {
		if v != "" {
			lines = append(lines, fmt.Sprintf("%s=%s", k, v))
		}
	}
	addInt("jc", p.Jc)
	addInt("jmin", p.Jmin)
	addInt("jmax", p.Jmax)
	addInt("s1", p.S1)
	addInt("s2", p.S2)
	addInt("s3", p.S3)
	addInt("s4", p.S4)
	addStr("h1", p.H1)
	addStr("h2", p.H2)
	addStr("h3", p.H3)
	addStr("h4", p.H4)
	addStr("i1", p.I1)
	addStr("i2", p.I2)
	addStr("i3", p.I3)
	addStr("i4", p.I4)
	addStr("i5", p.I5)
	return lines
}

// Validate checks Amnezia param constraints (best-effort; not exhaustive MTU math).
func (p AmneziaParams) Validate() error {
	if p.Jc < 0 || p.Jc > 128 {
		return fmt.Errorf("jc must be 0–128")
	}
	if p.Jmin < 0 || p.Jmax < 0 {
		return fmt.Errorf("jmin/jmax must be ≥ 0")
	}
	if p.Jmax > 0 && p.Jmin > p.Jmax {
		return fmt.Errorf("jmin must be ≤ jmax")
	}
	if p.S1 < 0 || p.S2 < 0 || p.S3 < 0 || p.S4 < 0 {
		return fmt.Errorf("s1–s4 must be ≥ 0")
	}
	if p.S1 > 0 && p.S2 > 0 && p.S1+56 == p.S2 {
		return fmt.Errorf("s1+56 must not equal s2")
	}
	hs := []string{p.H1, p.H2, p.H3, p.H4}
	set := map[string]struct{}{}
	for _, h := range hs {
		if h == "" {
			continue
		}
		if _, ok := set[h]; ok {
			return fmt.Errorf("h1–h4 must be unique when set")
		}
		set[h] = struct{}{}
	}
	return nil
}

// PairPort returns listen_port+10 (wrap-safe for UDP ports).
func PairPort(port int) int {
	if port <= 0 {
		return 0
	}
	p := port + 10
	if p > 65535 {
		p = port - 10
		if p < 1 {
			p = 1
		}
	}
	return p
}

// DefaultPairName derives the AWG twin interface name.
func DefaultPairName(wgName string) string {
	n := strings.TrimSpace(wgName)
	if n == "" {
		return "awg0"
	}
	if strings.HasSuffix(n, "-awg") {
		return n
	}
	// wg-owire-in → wg-owire-awg when name ends with -in
	if strings.HasSuffix(n, "-in") {
		return strings.TrimSuffix(n, "-in") + "-awg"
	}
	if strings.HasPrefix(n, "wg") && !strings.HasPrefix(n, "awg") {
		return "awg" + strings.TrimPrefix(n, "wg")
	}
	return n + "-awg"
}
