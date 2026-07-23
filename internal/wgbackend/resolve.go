package wgbackend

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Binary paths / module names (overridable via HostOptions).
const (
	DefaultWireGuardGo  = "wireguard-go"
	DefaultAmneziaWGGo  = "amneziawg-go"
	DefaultAWGTool      = "awg"
	DefaultWGTool       = "wg"
	ModuleWireGuard     = "wireguard"
	ModuleAmneziaWG     = "amneziawg"
	UserspaceSockDirWG  = "/var/run/wireguard"
	UserspaceSockDirAWG = "/var/run/amneziawg"
)

// CapabilityProbe discovers which backends the host can run.
type CapabilityProbe struct {
	runner Runner

	mu      sync.Mutex
	cached  bool
	caps    BackendCaps
	wgGo    string
	awgGo   string
	awgTool string
	wgTool  string
}

// BackendCaps is a snapshot of host capabilities.
type BackendCaps struct {
	KernelWG         bool `json:"kernel_wg"`
	UserspaceWG      bool `json:"userspace_wg"` // wireguard-go binary present
	KernelAmnezia    bool `json:"kernel_amnezia"`
	UserspaceAmnezia bool `json:"userspace_amnezia"` // amneziawg-go binary present
	AWGTool          bool `json:"awg_tool"`          // awg CLI present
}

// NewCapabilityProbe creates a probe using runner for lookups.
func NewCapabilityProbe(r Runner, wgGo, awgGo, awgTool string) *CapabilityProbe {
	if r == nil {
		r = ExecRunner{}
	}
	if wgGo == "" {
		wgGo = DefaultWireGuardGo
	}
	if awgGo == "" {
		awgGo = DefaultAmneziaWGGo
	}
	if awgTool == "" {
		awgTool = DefaultAWGTool
	}
	return &CapabilityProbe{
		runner:  r,
		wgGo:    wgGo,
		awgGo:   awgGo,
		awgTool: awgTool,
		wgTool:  DefaultWGTool,
	}
}

// Caps returns (and caches) host backend capabilities.
func (p *CapabilityProbe) Caps(ctx context.Context) BackendCaps {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cached {
		return p.caps
	}
	p.caps = BackendCaps{
		KernelWG:         moduleLoaded(ModuleWireGuard) || p.canIPLinkType(ctx, "wireguard"),
		UserspaceWG:      p.binaryExists(ctx, p.wgGo),
		KernelAmnezia:    moduleLoaded(ModuleAmneziaWG) || p.canIPLinkType(ctx, "amneziawg"),
		UserspaceAmnezia: p.binaryExists(ctx, p.awgGo),
		AWGTool:          p.binaryExists(ctx, p.awgTool),
	}
	p.cached = true
	return p.caps
}

// Invalidate forces a re-probe on next Caps call.
func (p *CapabilityProbe) Invalidate() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cached = false
}

func (p *CapabilityProbe) binaryExists(ctx context.Context, name string) bool {
	if name == "" {
		return false
	}
	if filepath.IsAbs(name) {
		st, err := os.Stat(name)
		return err == nil && !st.IsDir()
	}
	_, err := p.runner.Run(ctx, "sh", "-c", "command -v "+shellQuote(name))
	return err == nil
}

func (p *CapabilityProbe) canIPLinkType(ctx context.Context, kind string) bool {
	// `ip link help` lists types on stderr and usually exits non-zero.
	out, err := p.runner.Run(ctx, "ip", "link", "help")
	blob := out
	if err != nil {
		blob = err.Error() + "\n" + out
	}
	return strings.Contains(blob, kind)
}

func moduleLoaded(name string) bool {
	_, err := os.Stat(filepath.Join("/sys/module", name))
	return err == nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}

// ResolveBackend picks the concrete backend for a protocol + requested kind.
// Prefer kernel for performance/stability, then userspace go.
func (p *CapabilityProbe) ResolveBackend(ctx context.Context, protocol, requested string) (string, error) {
	proto, err := NormalizeProtocol(protocol)
	if err != nil {
		return "", err
	}
	req, err := NormalizeBackend(requested)
	if err != nil {
		return "", err
	}
	caps := p.Caps(ctx)

	if req != BackendAuto {
		// Validate explicit choice against protocol family.
		if proto == ProtocolAWG && !IsAmneziaBackend(req) {
			return "", fmt.Errorf("protocol awg requires amnezia_kernel or amnezia_go backend (got %s)", req)
		}
		if proto == ProtocolWG && IsAmneziaBackend(req) {
			// Allow amnezia backend with neutral params for dual-compat, but
			// stock protocol + amnezia backend is fine (AWG supersets WG).
			return req, nil
		}
		switch req {
		case BackendKernel:
			// still try even if probe missed; create may load module
		case BackendUserspace:
			if !caps.UserspaceWG {
				return "", fmt.Errorf("wireguard-go binary %q not found", p.wgGo)
			}
		case BackendAmneziaKernel:
			// may load module on create
		case BackendAmneziaGo:
			if !caps.UserspaceAmnezia {
				return "", fmt.Errorf("amneziawg-go binary %q not found", p.awgGo)
			}
		}
		return req, nil
	}

	// auto
	if proto == ProtocolAWG {
		if caps.KernelAmnezia {
			return BackendAmneziaKernel, nil
		}
		if caps.UserspaceAmnezia {
			return BackendAmneziaGo, nil
		}
		// Try kernel create even if module not yet loaded (modprobe on first use).
		return BackendAmneziaKernel, nil
	}
	// plain WG
	if caps.KernelWG {
		return BackendKernel, nil
	}
	if caps.UserspaceWG {
		return BackendUserspace, nil
	}
	return BackendKernel, nil
}
