package api

import (
	"net/http"
	"os/exec"
	"strings"

	"github.com/reloadlife/wireguardd/internal/version"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}
	status := "ready"
	if err := s.store.Ping(r.Context()); err != nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", err.Error())
		return
	}
	checks["db"] = "ok"

	bw := "none"
	if s.cfg != nil {
		bw = strings.ToLower(strings.TrimSpace(s.cfg.WireGuard.BandwidthBackend))
	}
	if bw == "" {
		bw = "tc"
	}
	checks["bandwidth_backend"] = bw
	switch bw {
	case "tc":
		if _, err := exec.LookPath("tc"); err != nil {
			checks["bandwidth_tc"] = "missing"
			status = "degraded"
		} else {
			checks["bandwidth_tc"] = "ok"
		}
	case "nft":
		if _, err := exec.LookPath("nft"); err != nil {
			checks["bandwidth_nft"] = "missing"
			status = "degraded"
		} else {
			checks["bandwidth_nft"] = "ok"
		}
	default:
		checks["bandwidth_tc"] = "n/a"
	}

	if s.cfg != nil && s.cfg.Webhooks.Enabled && strings.TrimSpace(s.cfg.Webhooks.URL) != "" {
		checks["webhooks"] = "enabled"
	} else {
		checks["webhooks"] = "disabled"
	}

	code := http.StatusOK
	writeJSON(w, code, map[string]any{"status": status, "checks": checks})
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, pkgapi.VersionInfo{
		Version: version.Version,
		Commit:  version.Commit,
		Date:    version.Date,
	})
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := pkgapi.DaemonConfig{
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
		DBPath:             s.cfg.DB.Path,
		TimeseriesPath:     s.cfg.DB.TimeseriesPath,
		ReadOnly:           s.cfg.ReadOnly,
	}
	if s.store != nil && cfg.TimeseriesPath == "" {
		cfg.TimeseriesPath = s.store.TimeseriesPath()
	}
	writeJSON(w, http.StatusOK, cfg)
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
