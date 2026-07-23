package api

import (
	"net/http"

	"github.com/reloadlife/wireguardd/internal/wgbackend"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

// handleBackends reports which WireGuard / Amnezia backends the host can run.
func (s *Server) handleBackends(w http.ResponseWriter, r *http.Request) {
	var caps pkgapi.BackendCapabilities
	if hb, ok := s.backend.(*wgbackend.HostBackend); ok {
		c := hb.Caps(r.Context())
		caps = pkgapi.BackendCapabilities{
			KernelWG:         c.KernelWG,
			UserspaceWG:      c.UserspaceWG,
			KernelAmnezia:    c.KernelAmnezia,
			UserspaceAmnezia: c.UserspaceAmnezia,
			AWGTool:          c.AWGTool,
		}
	} else {
		// Mock / tests: advertise everything so pair creation is not blocked.
		caps = pkgapi.BackendCapabilities{
			KernelWG: true, UserspaceWG: true,
			KernelAmnezia: true, UserspaceAmnezia: true, AWGTool: true,
		}
	}
	writeJSON(w, http.StatusOK, caps)
}
