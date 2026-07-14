package api

import (
	"net/http"

	"github.com/reloadlife/wireguardd/internal/version"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, pkgapi.VersionInfo{
		Version: version.Version,
		Commit:  version.Commit,
		Date:    version.Date,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, pkgapi.DaemonConfig{
		HTTPListen:         s.cfg.Listen.HTTP,
		UnixListen:         s.cfg.Listen.Unix,
		MetricsListen:      s.cfg.Listen.Metrics,
		SNMPEnabled:        s.cfg.SNMP.Enabled,
		SNMPListen:         s.cfg.SNMP.Listen,
		Persistence:        s.cfg.WireGuard.Persistence,
		ConfDir:            s.cfg.WireGuard.ConfDir,
		HandshakeConnected: s.cfg.WireGuard.HandshakeConnectedSec,
		SampleInterval:     s.cfg.WireGuard.SampleInterval,
		ReconcileInterval:  s.cfg.WireGuard.ReconcileInterval,
		AllowHooks:         s.cfg.WireGuard.AllowHooks,
		BandwidthBackend:   s.cfg.WireGuard.BandwidthBackend,
		ReadOnly:           s.cfg.ReadOnly,
	})
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	if err := s.ForceReconcile(r.Context()); err != nil {
		writeError(w, http.StatusInternalServerError, "reconcile_failed", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	ev, err := s.store.ListEvents(r.Context(), 200)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	out := make([]pkgapi.Event, 0, len(ev))
	for _, e := range ev {
		out = append(out, pkgapi.Event{
			ID: e.ID, TS: e.TS, Level: e.Level, Kind: e.Kind,
			Interface: e.Interface, PeerPublicKey: e.PeerPublicKey,
			Message: e.Message, Meta: e.Meta,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
