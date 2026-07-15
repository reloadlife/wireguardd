package api

import (
	"context"
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
	"github.com/reloadlife/wireguardd/internal/netutil"
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
	pub := ""
	if req.PublicKey != "" {
		var nerr error
		pub, nerr = wgutil.NormalizeKey(req.PublicKey)
		if nerr != nil {
			writeError(w, http.StatusBadRequest, "invalid_key", nerr.Error())
			return
		}
	} else if !req.GenerateClientKey && req.ClientPrivateKey == "" {
		writeError(w, http.StatusBadRequest, "validation", "public_key is required (or generate_client_key)")
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
	clientPriv := req.ClientPrivateKey
	// generate_client_key creates a full keypair and uses it as the peer identity.
	// Cannot invent a private key for an already-known public key.
	if req.GenerateClientKey && clientPriv == "" {
		if req.PublicKey != "" {
			writeError(w, http.StatusBadRequest, "validation", "generate_client_key cannot be used with public_key; omit public_key or pass client_private_key")
			return
		}
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
			return
		}
		clientPriv = kp.PrivateKey
		pub = kp.PublicKey
	}
	if clientPriv != "" {
		derived, err := crypto.PublicFromPrivate(clientPriv)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
			return
		}
		if pub == "" {
			pub = derived
		} else if pub != derived {
			writeError(w, http.StatusBadRequest, "validation", "client_private_key does not match public_key")
			return
		}
	}
	if pub == "" {
		writeError(w, http.StatusBadRequest, "validation", "public_key is required (or generate_client_key)")
		return
	}
	// Auto-allocate tunnel IP when neither allowed nor assigned IPs provided.
	allowed := req.AllowedIPs
	assigned := req.AssignedIPs
	if len(allowed) == 0 && len(assigned) == 0 {
		host, cidr, aerr := s.allocatePeerIP(r.Context(), name, iface, 0)
		if aerr != nil {
			writeError(w, http.StatusBadRequest, "validation", "ip auto-allocate: "+aerr.Error())
			return
		}
		assigned = []string{host}
		allowed = []string{cidr}
	}
	if err := netutil.ValidateCIDRList(allowed); err != nil {
		writeError(w, http.StatusBadRequest, "validation", "allowed_ips: "+err.Error())
		return
	}
	if err := netutil.ValidateIPOrCIDRList(assigned); err != nil {
		writeError(w, http.StatusBadRequest, "validation", "assigned_ips: "+err.Error())
		return
	}
	if req.Endpoint != "" {
		if err := netutil.ValidateEndpoint(req.Endpoint); err != nil {
			writeError(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
	}
	ka := req.PersistentKeepalive
	if ka == 0 && iface.DefaultKeepalive > 0 {
		ka = iface.DefaultKeepalive
	}
	expiresAt := strings.TrimSpace(req.ExpiresAt)
	if expiresAt != "" {
		if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
			if _, err2 := time.Parse(time.RFC3339Nano, expiresAt); err2 != nil {
				writeError(w, http.StatusBadRequest, "validation", "expires_at must be RFC3339")
				return
			}
		}
	}
	peer := &db.Peer{
		InterfaceID:         iface.ID,
		PublicKey:           pub,
		PresharedKey:        psk,
		ClientPrivateKey:    clientPriv,
		Name:                req.Name,
		Notes:               req.Notes,
		AllowedIPs:          allowed,
		AssignedIPs:         assigned,
		Endpoint:            req.Endpoint,
		PersistentKeepalive: ka,
		TrafficLimitBytes:   req.TrafficLimitBytes,
		ExpiresAt:           expiresAt,
		BandwidthRxBps:      req.BandwidthRxBps,
		BandwidthTxBps:      req.BandwidthTxBps,
		BandwidthTotalBps:   req.BandwidthTotalBps,
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
	if req.ClientPrivateKey != nil {
		priv := strings.TrimSpace(*req.ClientPrivateKey)
		if priv == "" {
			peer.ClientPrivateKey = ""
		} else {
			pub, err := crypto.PublicFromPrivate(priv)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid_key", "client_private_key invalid")
				return
			}
			if pub != peer.PublicKey {
				writeError(w, http.StatusBadRequest, "validation",
					"client_private_key does not match peer public_key (use POST .../issue-client-key with rotate=true to replace identity)")
				return
			}
			peer.ClientPrivateKey = priv
		}
	}
	if req.Name != nil {
		peer.Name = *req.Name
	}
	if req.Notes != nil {
		peer.Notes = *req.Notes
	}
	if req.AllowedIPs != nil {
		if err := netutil.ValidateCIDRList(req.AllowedIPs); err != nil {
			writeError(w, http.StatusBadRequest, "validation", "allowed_ips: "+err.Error())
			return
		}
		peer.AllowedIPs = req.AllowedIPs
	}
	if req.AssignedIPs != nil {
		if err := netutil.ValidateIPOrCIDRList(req.AssignedIPs); err != nil {
			writeError(w, http.StatusBadRequest, "validation", "assigned_ips: "+err.Error())
			return
		}
		peer.AssignedIPs = req.AssignedIPs
	}
	if req.Endpoint != nil {
		if err := netutil.ValidateEndpoint(*req.Endpoint); err != nil {
			writeError(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
		peer.Endpoint = *req.Endpoint
	}
	if req.PersistentKeepalive != nil {
		peer.PersistentKeepalive = *req.PersistentKeepalive
	}
	if req.TrafficLimitBytes != nil {
		peer.TrafficLimitBytes = *req.TrafficLimitBytes
	}
	if req.ExpiresAt != nil {
		expiresAt := strings.TrimSpace(*req.ExpiresAt)
		if expiresAt != "" {
			if _, err := time.Parse(time.RFC3339, expiresAt); err != nil {
				if _, err2 := time.Parse(time.RFC3339Nano, expiresAt); err2 != nil {
					writeError(w, http.StatusBadRequest, "validation", "expires_at must be RFC3339")
					return
				}
			}
		}
		peer.ExpiresAt = expiresAt
	}
	if req.BandwidthRxBps != nil {
		peer.BandwidthRxBps = *req.BandwidthRxBps
	}
	if req.BandwidthTxBps != nil {
		peer.BandwidthTxBps = *req.BandwidthTxBps
	}
	if req.BandwidthTotalBps != nil {
		peer.BandwidthTotalBps = *req.BandwidthTotalBps
	}
	if req.Tags != nil {
		peer.Tags = req.Tags
	}
	prevSuspended := peer.Suspended
	if req.Suspended != nil {
		peer.Suspended = *req.Suspended
	}
	if err := s.store.UpdatePeer(r.Context(), peer); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", name, peer.PublicKey, "peer updated", "{}")
	// PATCH suspended=true/false also emits enforce so webhooks/routes stay consistent
	// with dedicated suspend/resume endpoints.
	if req.Suspended != nil && *req.Suspended != prevSuspended {
		msg := "peer resumed"
		if *req.Suspended {
			msg = "peer suspended"
		}
		_ = s.store.AddEvent(r.Context(), "info", "enforce", name, peer.PublicKey, msg, `{"via":"patch"}`)
	}
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
		status := http.StatusBadRequest
		code := "client_config"
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
			code = "not_found"
		}
		writeError(w, status, code, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, pkgapi.ClientConfigResponse{Config: cfg})
}

// handleIssueClientKey stores or generates a client private key for conf/QR export.
//
// Adopted peers only have a public key (the private key lives on the phone/laptop).
// To produce a client conf you must either:
//   - PATCH client_private_key if you still have the original key, or
//   - POST here with {"rotate":true} to mint a new keypair (old client stops working
//     until it imports the new config).
func (s *Server) handleIssueClientKey(w http.ResponseWriter, r *http.Request) {
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
	var req pkgapi.IssueClientKeyRequest
	if r.Body != nil && r.ContentLength != 0 {
		if err := decodeJSON(r, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
			return
		}
	}
	// Also accept ?rotate=1
	if r.URL.Query().Get("rotate") == "1" || r.URL.Query().Get("rotate") == "true" {
		req.Rotate = true
	}

	prevPub := peer.PublicKey
	rotated := false

	if peer.ClientPrivateKey != "" && !req.Rotate {
		// Already have a key — just return conf.
		cfg, err := s.buildClientConfig(r, name, peer.PublicKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "client_config", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, pkgapi.IssueClientKeyResponse{
			Peer:             s.toAPIPeer(peer, false),
			ClientPrivateKey: peer.ClientPrivateKey,
			Config:           cfg,
			Rotated:          false,
		})
		return
	}

	if !req.Rotate && peer.ClientPrivateKey == "" {
		writeError(w, http.StatusBadRequest, "client_key_missing",
			"peer has no client_private_key (common after adopt). "+
				"Either PATCH client_private_key with the original key, or POST with {\"rotate\":true} "+
				"to generate a new keypair (client must re-import the config).")
		return
	}

	// Mint a new keypair and replace peer identity.
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
		return
	}
	peer.PublicKey = kp.PublicKey
	peer.ClientPrivateKey = kp.PrivateKey
	// Soft-reset counters against the new kernel peer (will be 0 after reconcile).
	peer.RxBytesOffset = 0
	peer.TxBytesOffset = 0
	peer.LastRxBytes = 0
	peer.LastTxBytes = 0
	if err := s.store.UpdatePeer(r.Context(), peer); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	// Drop samples for old identity; new peer_id is same row id.
	_ = s.store.AddEvent(r.Context(), "warn", "audit", name, kp.PublicKey,
		"client key issued (rotated peer public key; old client config invalid)",
		fmt.Sprintf(`{"previous_public_key":%q}`, prevPub))
	_ = s.ForceReconcile(r.Context())
	rotated = true

	cfg, err := s.buildClientConfig(r, name, peer.PublicKey)
	if err != nil {
		// Key is stored; conf may still fail if public_endpoint missing.
		writeJSON(w, http.StatusOK, pkgapi.IssueClientKeyResponse{
			Peer:              s.toAPIPeer(peer, true),
			ClientPrivateKey:  peer.ClientPrivateKey,
			PreviousPublicKey: prevPub,
			Config:            "",
			Rotated:           rotated,
		})
		return
	}
	writeJSON(w, http.StatusOK, pkgapi.IssueClientKeyResponse{
		Peer:              s.toAPIPeer(peer, true),
		ClientPrivateKey:  peer.ClientPrivateKey,
		PreviousPublicKey: prevPub,
		Config:            cfg,
		Rotated:           rotated,
	})
}

func (s *Server) handlePeerQR(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	pubkey := chi.URLParam(r, "pubkey")
	if n, err := wgutil.PathUnescapeKey(pubkey); err == nil {
		pubkey = n
	}
	cfg, err := s.buildClientConfig(r, name, pubkey)
	if err != nil {
		status := http.StatusBadRequest
		code := "client_config"
		if strings.Contains(err.Error(), "not found") {
			status = http.StatusNotFound
			code = "not_found"
		}
		writeError(w, status, code, err.Error())
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
	if peer.ClientPrivateKey == "" {
		return "", errors.New("peer has no client_private_key (typical for adopted peers). " +
			"PATCH client_private_key if you have it, or POST /v1/interfaces/{iface}/peers/{pubkey}/issue-client-key with {\"rotate\":true}")
	}
	addrs := peer.AssignedIPs
	if len(addrs) == 0 {
		for _, a := range peer.AllowedIPs {
			if strings.HasSuffix(a, "/32") || strings.HasSuffix(a, "/128") {
				addrs = append(addrs, a)
			}
		}
	}
	// Address lines need CIDR; bare IPs get /32 or /128.
	normAddrs := make([]string, 0, len(addrs))
	for _, a := range addrs {
		if strings.Contains(a, "/") {
			normAddrs = append(normAddrs, a)
			continue
		}
		if strings.Contains(a, ":") {
			normAddrs = append(normAddrs, a+"/128")
		} else {
			normAddrs = append(normAddrs, a+"/32")
		}
	}
	serverEndpoint := iface.PublicEndpoint
	if serverEndpoint == "" && iface.ListenPort > 0 {
		serverEndpoint = fmt.Sprintf("SERVER_PUBLIC_IP:%d", iface.ListenPort)
	}
	if serverEndpoint == "" {
		return "", errors.New("interface public_endpoint not set (required for client config)")
	}
	clientAllowed := []string{"0.0.0.0/0", "::/0"}
	cfg := &confparse.Config{
		Interface: confparse.InterfaceSection{
			PrivateKey: peer.ClientPrivateKey,
			Address:    normAddrs,
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

// allocatePeerIP finds the next free host IP on an interface.
// skipPeerID excludes that peer's current addresses (for re-allocation on edit).
func (s *Server) allocatePeerIP(ctx context.Context, ifaceName string, iface *db.Interface, skipPeerID int64) (assigned, allowed string, err error) {
	peers, err := s.store.ListPeersByInterface(ctx, ifaceName)
	if err != nil {
		return "", "", err
	}
	var peerAssigned, peerAllowed [][]string
	for _, p := range peers {
		if skipPeerID != 0 && p.ID == skipPeerID {
			continue
		}
		peerAssigned = append(peerAssigned, p.AssignedIPs)
		peerAllowed = append(peerAllowed, p.AllowedIPs)
	}
	used := netutil.CollectUsedHosts(iface.Addresses, peerAssigned, peerAllowed)
	return netutil.AllocateNextHost(iface.Addresses, used)
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
	effRx, effTx := p.EffectiveRx(), p.EffectiveTx()
	traffic := pkgapi.PeerTraffic{
		Total: pkgapi.TrafficBytes{RxBytes: effRx, TxBytes: effTx},
		Rate: pkgapi.TrafficRates{
			RxBps: p.LastRxBps, TxBps: p.LastTxBps,
		},
	}
	// Prefer live cache for raw rates + lookback windows (time-based).
	if s.cache != nil {
		if st, ok := s.cache.GetPeer(p.InterfaceName, p.PublicKey); ok {
			traffic.Rate.RxBps = st.RxBps
			traffic.Rate.TxBps = st.TxBps
			traffic.Rate.RxBpsRaw = st.RxBpsRaw
			traffic.Rate.TxBpsRaw = st.TxBpsRaw
			traffic.Rate.IntervalSec = st.IntervalSec
			if len(st.Windows) > 0 {
				traffic.Windows = make(map[string]pkgapi.TrafficWindow, len(st.Windows))
				for k, w := range st.Windows {
					traffic.Windows[k] = pkgapi.TrafficWindow{
						RxBytes: w.RxBytes, TxBytes: w.TxBytes,
						RxBpsAvg: w.RxBpsAvg, TxBpsAvg: w.TxBpsAvg, SpanSec: w.SpanSec,
					}
				}
			}
			// Prefer cache totals if present (same as DB after sample).
			if st.RxBytes > 0 || st.TxBytes > 0 || st.UpdatedAt.After(p.UpdatedAt) {
				traffic.Total.RxBytes = st.RxBytes
				traffic.Total.TxBytes = st.TxBytes
				effRx, effTx = st.RxBytes, st.TxBytes
			}
		}
	}
	out := pkgapi.Peer{
		ID: p.ID, InterfaceName: p.InterfaceName, PublicKey: p.PublicKey,
		Name: p.Name, Notes: p.Notes, AllowedIPs: p.AllowedIPs, AssignedIPs: p.AssignedIPs,
		Endpoint: p.Endpoint, PersistentKeepalive: p.PersistentKeepalive,
		Suspended: p.Suspended, TrafficLimitBytes: p.TrafficLimitBytes, ExpiresAt: p.ExpiresAt,
		BandwidthRxBps: p.BandwidthRxBps, BandwidthTxBps: p.BandwidthTxBps,
		BandwidthTotalBps: p.BandwidthTotalBps,
		FirstHandshakeAt:  p.FirstHandshakeAt, LastHandshakeAt: p.LastHandshakeAt,
		ConnectedSince: p.ConnectedSince, LastEndpoint: p.LastEndpoint,
		RxBytes: effRx, TxBytes: effTx,
		RxBps: traffic.Rate.RxBps, TxBps: traffic.Rate.TxBps,
		Traffic: traffic, Connected: connected,
		Tags: p.Tags, CreatedAt: p.CreatedAt, UpdatedAt: p.UpdatedAt,
	}
	if reveal {
		out.PresharedKey = p.PresharedKey
	}
	return out
}

// ensure fmt used for errors in file if needed
var _ = fmt.Sprintf
