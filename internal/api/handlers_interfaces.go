package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/reloadlife/wireguardd/internal/confparse"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func (s *Server) handleListInterfaces(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.ListInterfaces(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	out := make([]pkgapi.Interface, 0, len(list))
	for i := range list {
		out = append(out, s.toAPIInterface(r.Context(), &list[i], false))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	reveal := r.URL.Query().Get("reveal") == "1"
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "interface not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.toAPIInterface(r.Context(), iface, reveal))
}

func (s *Server) handleCreateInterface(w http.ResponseWriter, r *http.Request) {
	var req pkgapi.InterfaceCreateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "validation", "name is required")
		return
	}
	if !s.cfg.WireGuard.AllowHooks && (req.PreUp != "" || req.PostUp != "" || req.PreDown != "" || req.PostDown != "") {
		writeError(w, http.StatusBadRequest, "hooks_disabled", "hooks are disabled; set wireguard.allow_hooks=true")
		return
	}
	priv := req.PrivateKey
	pub := ""
	if priv == "" {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
			return
		}
		priv, pub = kp.PrivateKey, kp.PublicKey
	} else {
		var err error
		pub, err = crypto.PublicFromPrivate(priv)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
			return
		}
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	tableMode := req.TableMode
	if tableMode == "" {
		tableMode = "auto"
	}
	iface := &db.Interface{
		Name:             req.Name,
		PrivateKey:       priv,
		PublicKey:        pub,
		ListenPort:       req.ListenPort,
		FwMark:           req.FwMark,
		MTU:              req.MTU,
		TableMode:        tableMode,
		TableID:          req.TableID,
		DNS:              req.DNS,
		Addresses:        req.Addresses,
		PreUp:            req.PreUp,
		PostUp:           req.PostUp,
		PreDown:          req.PreDown,
		PostDown:         req.PostDown,
		DefaultKeepalive: req.DefaultKeepalive,
		PublicEndpoint:   req.PublicEndpoint,
		Enabled:          enabled,
	}
	if err := s.store.CreateInterface(r.Context(), iface); err != nil {
		writeError(w, http.StatusConflict, "create_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", iface.Name, "", "interface created", "{}")
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusCreated, s.toAPIInterface(r.Context(), iface, true))
}

func (s *Server) handleUpdateInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	var req pkgapi.InterfaceUpdateRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	if req.PrivateKey != nil {
		pub, err := crypto.PublicFromPrivate(*req.PrivateKey)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
			return
		}
		iface.PrivateKey = *req.PrivateKey
		iface.PublicKey = pub
	}
	if req.ListenPort != nil {
		iface.ListenPort = *req.ListenPort
	}
	if req.FwMark != nil {
		iface.FwMark = *req.FwMark
	}
	if req.MTU != nil {
		iface.MTU = *req.MTU
	}
	if req.TableMode != nil {
		iface.TableMode = *req.TableMode
	}
	if req.TableID != nil {
		iface.TableID = req.TableID
	}
	if req.DNS != nil {
		iface.DNS = req.DNS
	}
	if req.Addresses != nil {
		iface.Addresses = req.Addresses
	}
	if req.PreUp != nil || req.PostUp != nil || req.PreDown != nil || req.PostDown != nil {
		if !s.cfg.WireGuard.AllowHooks {
			writeError(w, http.StatusBadRequest, "hooks_disabled", "hooks are disabled")
			return
		}
	}
	if req.PreUp != nil {
		iface.PreUp = *req.PreUp
	}
	if req.PostUp != nil {
		iface.PostUp = *req.PostUp
	}
	if req.PreDown != nil {
		iface.PreDown = *req.PreDown
	}
	if req.PostDown != nil {
		iface.PostDown = *req.PostDown
	}
	if req.DefaultKeepalive != nil {
		iface.DefaultKeepalive = *req.DefaultKeepalive
	}
	if req.PublicEndpoint != nil {
		iface.PublicEndpoint = *req.PublicEndpoint
	}
	if req.Enabled != nil {
		iface.Enabled = *req.Enabled
	}
	if err := s.store.UpdateInterface(r.Context(), iface); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", iface.Name, "", "interface updated", "{}")
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusOK, s.toAPIInterface(r.Context(), iface, false))
}

func (s *Server) handleDeleteInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	ctx := r.Context()
	do := func() error {
		if err := s.store.DeleteInterface(ctx, name); err != nil {
			return err
		}
		if err := s.backend.RemoveInterface(ctx, name); err != nil {
			s.log.Debug("remove interface backend", "err", err)
		}
		return nil
	}
	var err error
	if s.reconciler != nil {
		err = s.reconciler.Exclusive(do)
	} else {
		err = do()
	}
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			writeError(w, http.StatusNotFound, "not_found", "interface not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(ctx, "info", "audit", name, "", "interface deleted", "{}")
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInterfaceUp(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	iface.Enabled = true
	if err := s.store.UpdateInterface(r.Context(), iface); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	if err := s.ForceReconcile(r.Context()); err != nil {
		s.log.Error("reconcile after up", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "up"})
}

func (s *Server) handleInterfaceDown(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	iface.Enabled = false
	if err := s.store.UpdateInterface(r.Context(), iface); err != nil {
		writeError(w, http.StatusInternalServerError, "update_failed", err.Error())
		return
	}
	if err := s.ForceReconcile(r.Context()); err != nil {
		s.log.Error("reconcile after down", "err", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "down"})
}

func (s *Server) handleInterfaceExport(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	iface, err := s.store.GetInterfaceByName(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusNotFound, "not_found", "interface not found")
		return
	}
	peers, err := s.store.ListPeersByInterface(r.Context(), name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	content := renderIfaceConf(iface, peers)
	path := filepath.Join(s.cfg.WireGuard.ConfDir, name+".conf")
	export := func() error {
		return s.backend.ExportConf(r.Context(), path, content)
	}
	var expErr error
	if s.reconciler != nil {
		expErr = s.reconciler.Exclusive(export)
	} else {
		expErr = export()
	}
	if expErr != nil {
		writeError(w, http.StatusInternalServerError, "export_failed", expErr.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"path": path})
}

func (s *Server) handleInterfaceImport(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	var req pkgapi.ImportConfRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return
	}
	cfg, err := confparse.Parse(req.Content)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_conf", err.Error())
		return
	}
	if req.Name != "" {
		name = req.Name
	}
	if name == "" {
		writeError(w, http.StatusBadRequest, "validation", "name required")
		return
	}
	pub, err := crypto.PublicFromPrivate(cfg.Interface.PrivateKey)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_key", err.Error())
		return
	}
	tableMode := "auto"
	var tableID *int
	if cfg.Interface.Table != "" {
		switch strings.ToLower(cfg.Interface.Table) {
		case "off", "auto":
			tableMode = strings.ToLower(cfg.Interface.Table)
		default:
			tableMode = "number"
			var n int
			if _, err := parseInt(cfg.Interface.Table, &n); err != nil {
				writeError(w, http.StatusBadRequest, "invalid_table", "Table must be auto, off, or a number")
				return
			}
			tableID = &n
		}
	}
	iface := &db.Interface{
		Name:       name,
		PrivateKey: cfg.Interface.PrivateKey,
		PublicKey:  pub,
		ListenPort: cfg.Interface.ListenPort,
		FwMark:     cfg.Interface.FwMark,
		MTU:        cfg.Interface.MTU,
		TableMode:  tableMode,
		TableID:    tableID,
		DNS:        cfg.Interface.DNS,
		Addresses:  cfg.Interface.Address,
		PreUp:      cfg.Interface.PreUp,
		PostUp:     cfg.Interface.PostUp,
		PreDown:    cfg.Interface.PreDown,
		PostDown:   cfg.Interface.PostDown,
		Enabled:    true,
	}
	peers := make([]db.Peer, 0, len(cfg.Peers))
	for _, p := range cfg.Peers {
		peers = append(peers, db.Peer{
			PublicKey:           p.PublicKey,
			PresharedKey:        p.PresharedKey,
			AllowedIPs:          p.AllowedIPs,
			Endpoint:            p.Endpoint,
			PersistentKeepalive: p.PersistentKeepalive,
		})
	}
	if err := s.store.ImportInterface(r.Context(), iface, peers); err != nil {
		writeError(w, http.StatusInternalServerError, "import_failed", err.Error())
		return
	}
	_ = s.ForceReconcile(r.Context())
	// reload
	iface, _ = s.store.GetInterfaceByName(r.Context(), name)
	writeJSON(w, http.StatusOK, s.toAPIInterface(r.Context(), iface, false))
}

func parseInt(s string, n *int) (int, error) {
	var v int
	_, err := fmtSscanf(s, &v)
	if err != nil {
		return 0, err
	}
	*n = v
	return v, nil
}

// tiny indirection to avoid importing fmt in many places incorrectly
func fmtSscanf(s string, n *int) (int, error) {
	var v int
	_, err := parseScan(s, &v)
	*n = v
	return v, err
}

func parseScan(s string, n *int) (int, error) {
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not int")
		}
	}
	v := 0
	for _, c := range s {
		v = v*10 + int(c-'0')
	}
	*n = v
	return 1, nil
}

func renderIfaceConf(iface *db.Interface, peers []db.Peer) string {
	table := iface.TableMode
	if iface.TableMode == "number" && iface.TableID != nil {
		table = fmt.Sprintf("%d", *iface.TableID)
	}
	cfg := &confparse.Config{
		Interface: confparse.InterfaceSection{
			PrivateKey: iface.PrivateKey,
			Address:    iface.Addresses,
			ListenPort: iface.ListenPort,
			DNS:        iface.DNS,
			MTU:        iface.MTU,
			Table:      table,
			FwMark:     iface.FwMark,
			PreUp:      iface.PreUp,
			PostUp:     iface.PostUp,
			PreDown:    iface.PreDown,
			PostDown:   iface.PostDown,
		},
	}
	for _, p := range peers {
		allowed := p.AllowedIPs
		if p.Suspended {
			allowed = nil
		}
		ps := confparse.PeerSection{
			PublicKey:           p.PublicKey,
			PresharedKey:        p.PresharedKey,
			AllowedIPs:          allowed,
			Endpoint:            p.Endpoint,
			PersistentKeepalive: p.PersistentKeepalive,
			Name:                p.Name,
			Notes:               p.Notes,
			TrafficLimit:        p.TrafficLimitBytes,
		}
		if len(p.AssignedIPs) > 0 {
			ps.Address = p.AssignedIPs[0]
		}
		cfg.Peers = append(cfg.Peers, ps)
	}
	return confparse.Render(cfg)
}

func (s *Server) toAPIInterface(ctx context.Context, iface *db.Interface, reveal bool) pkgapi.Interface {
	peers, _ := s.store.ListPeersByInterface(ctx, iface.Name)
	var rx, tx int64
	var rxBps, txBps float64
	for _, p := range peers {
		rx += p.EffectiveRx()
		tx += p.EffectiveTx()
		rxBps += p.LastRxBps
		txBps += p.LastTxBps
	}
	up := iface.Enabled
	if dev, err := s.backend.Device(ctx, iface.Name); err == nil {
		up = dev.Up && iface.Enabled
		_ = dev.ListenPort // live port observed; response uses desired ListenPort
	}
	out := pkgapi.Interface{
		ID: iface.ID, Name: iface.Name, PublicKey: iface.PublicKey,
		ListenPort: iface.ListenPort, FwMark: iface.FwMark, MTU: iface.MTU,
		TableMode: iface.TableMode, TableID: iface.TableID, DNS: iface.DNS,
		Addresses: iface.Addresses, DefaultKeepalive: iface.DefaultKeepalive,
		PublicEndpoint: iface.PublicEndpoint,
		Enabled:        iface.Enabled, Up: up, PeerCount: len(peers),
		RxBytes: rx, TxBytes: tx, RxBps: rxBps, TxBps: txBps,
		CreatedAt: iface.CreatedAt, UpdatedAt: iface.UpdatedAt,
	}
	if s.cfg.WireGuard.AllowHooks {
		out.PreUp, out.PostUp, out.PreDown, out.PostDown = iface.PreUp, iface.PostUp, iface.PreDown, iface.PostDown
	}
	if reveal {
		out.PrivateKey = iface.PrivateKey
	}
	return out
}

// silence unused import if time not used elsewhere in future
var _ = time.Time{}
