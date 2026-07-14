package api

import (
	"net/http"

	"github.com/reloadlife/wireguardd/internal/adopt"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func (s *Server) adoptService() *adopt.Service {
	confDir := "/etc/wireguard"
	if s.cfg != nil && s.cfg.WireGuard.ConfDir != "" {
		confDir = s.cfg.WireGuard.ConfDir
	}
	return adopt.New(s.store, s.backend, confDir, s.log)
}

func (s *Server) handleDiscover(w http.ResponseWriter, r *http.Request) {
	opts := adopt.Options{ReadConf: true}
	// Optional ?name=wg0&name=wg1
	if names := r.URL.Query()["name"]; len(names) > 0 {
		opts.Names = names
	}
	if r.URL.Query().Get("read_conf") == "0" || r.URL.Query().Get("read_conf") == "false" {
		opts.ReadConf = false
	}
	rep, err := s.adoptService().Discover(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "discover_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, toAPIAdoptReport(rep))
}

func (s *Server) handleAdopt(w http.ResponseWriter, r *http.Request) {
	var req pkgapi.AdoptRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
	}
	readConf := true
	if req.ReadConf != nil {
		readConf = *req.ReadConf
	}
	opts := adopt.Options{
		Names:     req.Names,
		ReadConf:  readConf,
		Overwrite: req.Overwrite,
	}
	rep, err := s.adoptService().Adopt(r.Context(), opts)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "adopt_failed", err.Error())
		return
	}
	// Kick reconcile so stats/cache populate without host disruption.
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusOK, toAPIAdoptReport(rep))
}

func toAPIAdoptReport(rep *adopt.Report) pkgapi.AdoptReport {
	if rep == nil {
		return pkgapi.AdoptReport{}
	}
	out := pkgapi.AdoptReport{At: rep.At}
	for _, p := range rep.Preview {
		out.Preview = append(out.Preview, pkgapi.AdoptPreview{
			Name: p.Name, PublicKey: p.PublicKey, HasPrivateKey: p.HasPrivateKey,
			ListenPort: p.ListenPort, FwMark: p.FwMark, MTU: p.MTU,
			Addresses: p.Addresses, PeerCount: p.PeerCount, Up: p.Up,
			ConfPath: p.ConfPath, ConfLoaded: p.ConfLoaded, AlreadyInDB: p.AlreadyInDB,
			TableMode: p.TableMode, Notes: p.Notes,
		})
	}
	for _, r := range rep.Results {
		out.Results = append(out.Results, pkgapi.AdoptResult{
			Name: r.Name, Action: r.Action, HasPrivateKey: r.HasPrivateKey,
			PeerCount: r.PeerCount, ConfLoaded: r.ConfLoaded, Error: r.Error, Notes: r.Notes,
		})
	}
	return out
}
