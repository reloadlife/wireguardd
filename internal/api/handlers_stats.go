package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	ifaces, err := s.store.ListInterfaces(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	peers, err := s.store.ListAllPeers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	sum := pkgapi.StatsSummary{
		Interfaces: len(ifaces),
		Peers:      len(peers),
	}
	now := time.Now().UTC()
	for _, p := range peers {
		sum.RxBytes += p.EffectiveRx()
		sum.TxBytes += p.EffectiveTx()
		sum.RxBps += p.LastRxBps
		sum.TxBps += p.LastTxBps
		if p.Suspended {
			sum.Suspended++
		}
		if p.LastHandshakeAt != "" {
			if hs, err := time.Parse(time.RFC3339Nano, p.LastHandshakeAt); err == nil {
				if now.Sub(hs) <= time.Duration(s.handshake)*time.Second {
					sum.Connected++
				}
			}
		}
	}
	writeJSON(w, http.StatusOK, sum)
}

func (s *Server) handleAllPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := s.store.ListAllPeers(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	out := make([]pkgapi.Peer, 0, len(peers))
	for i := range peers {
		out = append(out, s.toAPIPeer(&peers[i], false))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleInterfaceStats(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	apiIface := s.toAPIInterface(r.Context(), iface, false)
	writeJSON(w, http.StatusOK, apiIface)
}
