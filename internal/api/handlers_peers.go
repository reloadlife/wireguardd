package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/skip2/go-qrcode"

	"github.com/reloadlife/wireguardd/internal/confparse"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
	"github.com/reloadlife/wireguardd/pkg/wgutil"
)

func (s *Server) handleListPeers(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if _, err := s.store.GetInterfaceByName(r.Context(), name); err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	peers, err := s.store.ListPeersByInterface(r.Context(), name)
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

func (s *Server) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey, err := wgutil.PathUnescapeKey(chi.URLParam(r, "pubkey"))
	if err != nil {
		// try raw
		pubkey = chi.URLParam(r, "pubkey")
	}
	reveal := r.URL.Query().Get("reveal") == "1"
	peer, err := s.store.GetPeer(r.Context(), name, pubkey)
	if err != nil {
		// try with original param if normalize changed it
		if peer, err = s.store.GetPeer(r.Context(), name, chi.URLParam(r, "pubkey")); err != nil {
			writeError(w, http.StatusNotFound, "not_found", "peer not found")
			return
		}
	}
	writeJSON(w, http.StatusOK, s.toAPIPeer(peer, reveal))
}

func (s *Server) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	var req pkgapi.PeerCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "validation", "public_key is required")
		return
	}
	pub, err := wgutil.NormalizeKey(req.PublicKey)
	if err != nil {
		// allow non-strict for tests using mock keys? require valid wireguard keys
		writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
		return
	}
	psk := req.PresharedKey
	if req.GeneratePSK {
		psk, err = crypto.GeneratePSK()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
			return
		}
	}
	ka := req.PersistentKeepalive
	if ka == 0 && iface.DefaultKeepalive > 0 {
		ka = iface.DefaultKeepalive
	}
	peer := &db.Peer{
		InterfaceID:         iface.ID,
		PublicKey:           pub,
		PresharedKey:        psk,
		Name:                req.Name,
		Notes:               req.Notes,
		AllowedIPs:          req.AllowedIPs,
		AssignedIPs:         req.AssignedIPs,
		Endpoint:            req.Endpoint,
		PersistentKeepalive: ka,
		TrafficLimitBytes:   req.TrafficLimitBytes,
		BandwidthRxBps:      req.BandwidthRxBps,
		BandwidthTxBps:      req.BandwidthTxBps,
		Tags:                req.Tags,
	}
	if err := s.store.CreatePeer(r.Context(), peer); err != nil {
		writeError(w, http.StatusConflict, "create_failed", err.Error())
		return
	}
	peer.InterfaceName = name
	_ = s.store.AddEvent(r.Context(), "info", "audit", name, pub, "peer created", "{}")
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusCreated, s.toAPIPeer(peer, true))
}

func (s *Server) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	peer, err := s.store.GetPeer(r.Context(), name, pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "peer not found")
		return
	}
	var req pkgapi.PeerUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.PresharedKey != nil {
		peer.PresharedKey = *req.PresharedKey
	}
	if req.Name != nil {
		peer.Name = *req.Name
	}
	if req.Notes != nil {
		peer.Notes = *req.Notes
	}
	if req.AllowedIPs != nil {
		peer.AllowedIPs = req.AllowedIPs
	}
	if req.AssignedIPs != nil {
		peer.AssignedIPs = req.AssignedIPs
	}
	if req.Endpoint != nil {
		peer.Endpoint = *req.Endpoint
	}
	if req.PersistentKeepalive != nil {
		peer.PersistentKeepalive = *req.PersistentKeepalive
	}
	if req.TrafficLimitBytes != nil {
		peer.TrafficLimitBytes = *req.TrafficLimitBytes
	}
	if req.BandwidthRxBps != nil {
		peer.BandwidthRxBps = *req.BandwidthRxBps
	}
	if req.BandwidthTxBps != nil {
		peer.BandwidthTxBps = *req.BandwidthTxBps
	}
	if req.Tags != nil {
		peer.Tags = req.Tags
	}
	if req.Suspended != nil {
		peer.Suspended = *req.Suspended
	}
	if err := s.store.UpdatePeer(r.Context(), peer); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", name, peer.PublicKey, "peer updated", "{}")
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusOK, s.toAPIPeer(peer, false))
}

func (s *Server) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	if err := s.store.DeletePeer(r.Context(), name, pubkey); err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "peer not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", name, pubkey, "peer deleted", "{}")
	_ = s.ForceReconcile(r.Context())
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleSuspendPeer(w http.ResponseWriter, r *http.Request) {
	s.setSuspend(w, r, true)
}

func (s *Server) handleResumePeer(w http.ResponseWriter, r *http.Request) {
	s.setSuspend(w, r, false)
}

func (s *Server) setSuspend(w http.ResponseWriter, r *http.Request, suspended bool) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	peer, err := s.store.GetPeer(r.Context(), name, pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "peer not found")
		return
	}
	if err := s.store.SetPeerSuspended(r.Context(), peer.ID, suspended); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	msg := "peer resumed"
	if suspended {
		msg = "peer suspended"
	}
	_ = s.store.AddEvent(r.Context(), "info", "enforce", name, pubkey, msg, "{}")
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"suspended": suspended})
}

func (s *Server) handleResetPeerTraffic(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	peer, err := s.store.GetPeer(r.Context(), name, pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "peer not found")
		return
	}
	if err := s.store.SoftResetPeerTraffic(r.Context(), peer.ID, peer.LastRxBytes, peer.LastTxBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", name, pubkey, "traffic counters reset", "{}")
	writeJSON(w, http.StatusOK, map[string]string{"status": "reset"})
}

func (s *Server) handlePeerClientConfig(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	cfg, err := s.buildClientConfig(r, name, pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pkgapi.ClientConfigResponse{Config: cfg})
}

func (s *Server) handlePeerQR(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	cfg, err := s.buildClientConfig(r, name, pubkey)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", err.Error())
		return
	}
	png, err := qrcode.Encode(cfg, qrcode.Medium, 256)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "qr_failed", err.Error())
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(png)
}

func (s *Server) buildClientConfig(r *http.Request, ifaceName, pubkey string) (string, error) {
	iface, err := s.store.GetInterfaceByName(r.Context(), ifaceName)
	if err != nil {
		return "", errors.New("interface not found")
	}
	peer, err := s.store.GetPeer(r.Context(), ifaceName, pubkey)
	if err != nil {
		return "", errors.New("peer not found")
	}
	// Client needs its own private key — we only have public key on server.
	// Emit a template with placeholders for client private key and server endpoint.
	addrs := peer.AssignedIPs
	if len(addrs) == 0 {
		// derive from allowed if /32
		for _, a := range peer.AllowedIPs {
			if strings.HasSuffix(a, "/32") || strings.HasSuffix(a, "/128") {
				addrs = append(addrs, a)
			}
		}
	}
	serverEndpoint := peer.Endpoint
	if serverEndpoint == "" {
		serverEndpoint = "SERVER_PUBLIC_IP:PORT"
	}
	// Note: For client config, AllowedIPs is typically 0.0.0.0/0 or LAN routes; use peer notes or default.
	clientAllowed := []string{"0.0.0.0/0", "::/0"}
	cfg := &confparse.Config{
		Interface: confparse.InterfaceSection{
			PrivateKey: "CLIENT_PRIVATE_KEY",
			Address:    addrs,
			DNS:        iface.DNS,
			MTU:        iface.MTU,
		},
		Peers: []confparse.PeerSection{{
			PublicKey:           iface.PublicKey,
			PresharedKey:        peer.PresharedKey,
			AllowedIPs:          clientAllowed,
			Endpoint:            serverEndpoint,
			PersistentKeepalive: peer.PersistentKeepalive,
		}},
	}
	return confparse.Render(cfg), nil
}

func (s *Server) toAPIPeer(p *db.Peer, reveal bool) pkgapi.Peer {
	connected := false
	if p.LastHandshakeAt != "" {
		if hs, err := time.Parse(time.RFC3339Nano, p.LastHandshakeAt); err == nil {
			if time.Since(hs) <= time.Duration(s.handshake)*time.Second {
				connected = true
			}
		}
	}
	out := pkgapi.Peer{
		ID: p.ID, InterfaceName: p.InterfaceName, PublicKey: p.PublicKey,
		Name: p.Name, Notes: p.Notes, AllowedIPs: p.AllowedIPs, AssignedIPs: p.AssignedIPs,
		Endpoint: p.Endpoint, PersistentKeepalive: p.PersistentKeepalive,
		Suspended: p.Suspended, TrafficLimitBytes: p.TrafficLimitBytes,
		BandwidthRxBps: p.BandwidthRxBps, BandwidthTxBps: p.BandwidthTxBps,
		FirstHandshakeAt: p.FirstHandshakeAt, LastHandshakeAt: p.LastHandshakeAt,
		ConnectedSince: p.ConnectedSince, LastEndpoint: p.LastEndpoint,
		RxBytes: p.EffectiveRx(), TxBytes: p.EffectiveTx(),
		RxBps: p.LastRxBps, TxBps: p.LastTxBps, Connected: connected,
		Tags: p.Tags, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if reveal {
		out.PresharedKey = p.PresharedKey
	}
	return out
}

// ensure fmt used for errors in file if needed
var _ = fmt.Sprintf
