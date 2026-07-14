package api

import (
	"net/http"
	"strconv"
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
	for i := range peers {
		apiP := s.toAPIPeer(&peers[i], false)
		sum.RxBytes += apiP.RxBytes
		sum.TxBytes += apiP.TxBytes
		sum.RxBps += apiP.RxBps
		sum.TxBps += apiP.TxBps
		sum.Traffic.Total.RxBytes += apiP.Traffic.Total.RxBytes
		sum.Traffic.Total.TxBytes += apiP.Traffic.Total.TxBytes
		sum.Traffic.Rate.RxBps += apiP.Traffic.Rate.RxBps
		sum.Traffic.Rate.TxBps += apiP.Traffic.Rate.TxBps
		sum.Traffic.Rate.RxBpsRaw += apiP.Traffic.Rate.RxBpsRaw
		sum.Traffic.Rate.TxBpsRaw += apiP.Traffic.Rate.TxBpsRaw
		if apiP.Suspended {
			sum.Suspended++
		}
		if apiP.Connected {
			sum.Connected++
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

// handlePeerTraffic returns dual counters + optional sample history.
// Query: ?from=RFC3339&to=RFC3339&limit=N  (defaults: last 1h, limit 720)
func (s *Server) handlePeerTraffic(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	peer, err := s.store.GetPeer(r.Context(), name, pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "peer not found")
		return
	}
	apiP := s.toAPIPeer(peer, false)

	now := time.Now().UTC()
	to := now
	from := now.Add(-time.Hour)
	if v := r.URL.Query().Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			to = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			to = t.UTC()
		}
	}
	if v := r.URL.Query().Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			from = t.UTC()
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			from = t.UTC()
		}
	}
	limit := 720
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}

	samples, err := s.store.ListPeerSamples(r.Context(), peer.ID, from, to, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	pts := make([]pkgapi.TrafficSamplePoint, 0, len(samples))
	for _, sm := range samples {
		pts = append(pts, pkgapi.TrafficSamplePoint{
			Time: sm.SampledAt, RxBytes: sm.RxBytes, TxBytes: sm.TxBytes,
			RxBps: sm.RxBps, TxBps: sm.TxBps,
		})
	}
	writeJSON(w, http.StatusOK, pkgapi.PeerTrafficHistory{
		Interface: name,
		PublicKey: peer.PublicKey,
		From:      from,
		To:        to,
		Traffic:   apiP.Traffic,
		Samples:   pts,
	})
}
