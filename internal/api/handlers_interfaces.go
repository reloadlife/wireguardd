package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/reloadlife/wireguardd/internal/wgbackend"

	"github.com/go-chi/chi/v5"

	"github.com/reloadlife/wireguardd/internal/confparse"
	"github.com/reloadlife/wireguardd/internal/crypto"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/netutil"
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
	if netutil.ReservedHostInterface(req.Name) {
		writeError(w, http.StatusConflict, "reserved_interface", netutil.ReservedHostInterfaceMessage(req.Name))
		return
	}
	if req.ListenPort < 0 || req.ListenPort > 65535 {
		writeError(w, http.StatusBadRequest, "validation", "listen_port must be 0-65535")
		return
	}
	if err := netutil.ValidateCIDRList(req.Addresses); err != nil {
		writeError(w, http.StatusBadRequest, "validation", "addresses: "+err.Error())
		return
	}
	if req.PublicEndpoint != "" {
		if err := netutil.ValidateEndpoint(req.PublicEndpoint); err != nil {
			writeError(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
	}
	if !s.cfg.WireGuard.AllowHooks && (req.PreUp != "" || req.PostUp != "" || req.PreDown != "" || req.PostDown != "") {
		writeError(w, http.StatusBadRequest, "hooks_disabled", "hooks are disabled; set wireguard.allow_hooks=true")
		return
	}
	priv := req.PrivateKey
	pub := ""
	if priv == "" {
		// Adopt the key of an interface that already exists in the kernel
		// rather than minting a new one.
		//
		// An interface's private key IS its identity: every peer that talks to
		// it holds the matching public key. Rotating it silently does not fail
		// loudly — WireGuard simply stops answering peers that no longer
		// recognise it, with no log line on either side, which is
		// indistinguishable from the link being down.
		//
		// That is what took sky-ams-1 off the control-plane mesh for over three
		// hours on 2026-07-19: mesh0 was recreated without a key while a
		// duplicate wireguardd unit was crash-looping, thr kept the old public
		// key in its peer list, and every handshake was silently dropped. SSH
		// and every daemon on the node were fine the whole time.
		//
		// node-agent already refuses to report mesh0 upward for this reason
		// ("CP desired-state would recreate an empty iface and wipe the thr
		// peer every reconcile"), but that guard only covers one caller. The
		// invariant belongs here, where the key is actually issued.
		if dev, err := s.backend.Device(r.Context(), req.Name); err == nil && dev != nil &&
			dev.PrivateKey != "" && !wgbackend.IsZeroKey(dev.PrivateKey) {
			priv = dev.PrivateKey
			if p, err := crypto.PublicFromPrivate(priv); err == nil {
				pub = p
			}
			s.log.Warn("adopted existing interface key instead of generating a new one",
				"iface", req.Name, "public_key", pub)
		}
	}
	if priv == "" {
		kp, err := crypto.GenerateKeyPair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "keygen_failed", err.Error())
			return
		}
		priv, pub = kp.PrivateKey, kp.PublicKey
	} else if pub == "" {
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
	backend, err := wgbackend.NormalizeBackend(req.Backend)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	protocol, err := wgbackend.NormalizeProtocol(req.Protocol)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation", err.Error())
		return
	}
	// Infer protocol from backend when not set.
	if req.Protocol == "" && wgbackend.IsAmneziaBackend(backend) {
		protocol = wgbackend.ProtocolAWG
	}
	amneziaJSON := ""
	if req.Amnezia != nil {
		ap := toBackendAmnezia(req.Amnezia)
		if err := ap.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, "validation", "amnezia: "+err.Error())
			return
		}
		amneziaJSON = encodeAmnezia(req.Amnezia)
	} else if protocol == wgbackend.ProtocolAWG {
		// Generate a durable noise preset so client configs stay stable.
		gen := fromBackendAmnezia(wgbackend.DefaultNoisePreset())
		amneziaJSON = encodeAmnezia(gen)
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
		Backend:          backend,
		Protocol:         protocol,
		AmneziaJSON:      amneziaJSON,
	}

	// Default dual pair: plain WG on PORT + AWG on PORT+10.
	if req.CreateAWGPair {
		if protocol == wgbackend.ProtocolAWG {
			writeError(w, http.StatusBadRequest, "validation", "create_awg_pair requires the primary interface to be protocol=wg")
			return
		}
		awgName := strings.TrimSpace(req.AWGName)
		if awgName == "" {
			awgName = wgbackend.DefaultPairName(req.Name)
		}
		if awgName == req.Name {
			writeError(w, http.StatusBadRequest, "validation", "awg_name must differ from primary name")
			return
		}
		awgBackend, err := wgbackend.NormalizeBackend(req.AWGBackend)
		if err != nil {
			writeError(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
		if awgBackend == wgbackend.BackendAuto {
			// Prefer amnezia family for the twin.
			awgBackend = wgbackend.BackendAuto
		}
		var awgParams *pkgapi.AmneziaParams
		if req.NeutralAWG {
			awgParams = fromBackendAmnezia(wgbackend.NeutralAmneziaParams())
		} else if req.AWGAmnezia != nil {
			ap := toBackendAmnezia(req.AWGAmnezia)
			if err := ap.Validate(); err != nil {
				writeError(w, http.StatusBadRequest, "validation", "awg_amnezia: "+err.Error())
				return
			}
			awgParams = req.AWGAmnezia
		} else {
			awgParams = fromBackendAmnezia(wgbackend.DefaultNoisePreset())
		}
		awgPort := wgbackend.PairPort(req.ListenPort)
		awgEndpoint := req.PublicEndpoint
		if awgEndpoint != "" && req.ListenPort > 0 {
			// Replace trailing :port with pair port when endpoint ends with primary port.
			if host, port, err := splitHostPort(awgEndpoint); err == nil && port == req.ListenPort {
				awgEndpoint = fmt.Sprintf("%s:%d", host, awgPort)
			}
		}
		awgAddrs := req.AWGAddresses
		iface.PairName = awgName
		if err := s.store.CreateInterface(r.Context(), iface); err != nil {
			writeError(w, http.StatusConflict, "create_failed", err.Error())
			return
		}
		awgIface := &db.Interface{
			Name:             awgName,
			PrivateKey:       priv, // same server identity so clients can try either endpoint
			PublicKey:        pub,
			ListenPort:       awgPort,
			FwMark:           req.FwMark,
			MTU:              req.MTU,
			TableMode:        tableMode,
			TableID:          req.TableID,
			DNS:              req.DNS,
			Addresses:        awgAddrs,
			PreUp:            req.PreUp,
			PostUp:           req.PostUp,
			PreDown:          req.PreDown,
			PostDown:         req.PostDown,
			DefaultKeepalive: req.DefaultKeepalive,
			PublicEndpoint:   awgEndpoint,
			Enabled:          enabled,
			Backend:          awgBackend,
			Protocol:         wgbackend.ProtocolAWG,
			AmneziaJSON:      encodeAmnezia(awgParams),
			PairName:         iface.Name,
		}
		if err := s.store.CreateInterface(r.Context(), awgIface); err != nil {
			_ = s.store.DeleteInterface(r.Context(), iface.Name)
			writeError(w, http.StatusConflict, "create_failed", "awg twin: "+err.Error())
			return
		}
		_ = s.store.AddEvent(r.Context(), "info", "audit", iface.Name, "", "interface pair created (wg+awg)",
			fmt.Sprintf(`{"awg":%q,"wg_port":%d,"awg_port":%d}`, awgName, iface.ListenPort, awgPort))
		_ = s.ForceReconcile(r.Context())
		writeJSON(w, http.StatusCreated, pkgapi.InterfacePairResponse{
			WG:  s.toAPIInterface(r.Context(), iface, true),
			AWG: s.toAPIInterface(r.Context(), awgIface, true),
		})
		return
	}

	if err := s.store.CreateInterface(r.Context(), iface); err != nil {
		writeError(w, http.StatusConflict, "create_failed", err.Error())
		return
	}
	_ = s.store.AddEvent(r.Context(), "info", "audit", iface.Name, "", "interface created", "{}")
	_ = s.ForceReconcile(r.Context())
	writeJSON(w, http.StatusCreated, s.toAPIInterface(r.Context(), iface, true))
}

func splitHostPort(ep string) (host string, port int, err error) {
	// net.SplitHostPort needs brackets for v6; reuse netutil-style parse.
	host, portStr, err := splitHostPortRaw(ep)
	if err != nil {
		return "", 0, err
	}
	var p int
	if _, err := fmt.Sscanf(portStr, "%d", &p); err != nil {
		return "", 0, err
	}
	return host, p, nil
}

func splitHostPortRaw(ep string) (host, port string, err error) {
	// last ':' separates port (handles host:port; not full v6 without brackets)
	i := strings.LastIndex(ep, ":")
	if i <= 0 || i == len(ep)-1 {
		return "", "", fmt.Errorf("invalid endpoint")
	}
	return ep[:i], ep[i+1:], nil
}

func (s *Server) handleUpdateInterface(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if netutil.ReservedHostInterface(name) {
		writeError(w, http.StatusConflict, "reserved_interface", netutil.ReservedHostInterfaceMessage(name))
		return
	}
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
		if *req.ListenPort < 0 || *req.ListenPort > 65535 {
			writeError(w, http.StatusBadRequest, "validation", "listen_port must be 0-65535")
			return
		}
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
		if err := netutil.ValidateCIDRList(req.Addresses); err != nil {
			writeError(w, http.StatusBadRequest, "validation", "addresses: "+err.Error())
			return
		}
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
		if *req.PublicEndpoint != "" {
			if err := netutil.ValidateEndpoint(*req.PublicEndpoint); err != nil {
				writeError(w, http.StatusBadRequest, "validation", err.Error())
				return
			}
		}
		iface.PublicEndpoint = *req.PublicEndpoint
	}
	if req.Enabled != nil {
		iface.Enabled = *req.Enabled
	}
	if req.Backend != nil {
		b, err := wgbackend.NormalizeBackend(*req.Backend)
		if err != nil {
			writeError(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
		iface.Backend = b
	}
	if req.Protocol != nil {
		p, err := wgbackend.NormalizeProtocol(*req.Protocol)
		if err != nil {
			writeError(w, http.StatusBadRequest, "validation", err.Error())
			return
		}
		iface.Protocol = p
	}
	if req.Amnezia != nil {
		ap := toBackendAmnezia(req.Amnezia)
		if err := ap.Validate(); err != nil {
			writeError(w, http.StatusBadRequest, "validation", "amnezia: "+err.Error())
			return
		}
		iface.AmneziaJSON = encodeAmnezia(req.Amnezia)
	}
	if req.PairName != nil {
		iface.PairName = *req.PairName
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
	// Reserved control-plane meshes (mesh0) must never be torn down by
	// wireguardd. If a stale row exists in the DB from a past adopt, purge the
	// row only — leave the kernel interface and its peers untouched.
	if netutil.ReservedHostInterface(name) {
		if err := s.store.DeleteInterface(ctx, name); err != nil {
			if errors.Is(err, db.ErrNotFound) {
				writeError(w, http.StatusConflict, "reserved_interface", netutil.ReservedHostInterfaceMessage(name))
				return
			}
			writeError(w, http.StatusInternalServerError, "delete_failed", err.Error())
			return
		}
		_ = s.store.AddEvent(ctx, "info", "audit", name, "",
			"reserved interface purged from DB only (kernel left intact)", "{}")
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":      true,
			"name":    name,
			"kernel":  "left_intact",
			"message": "removed reserved interface from wireguardd DB only",
		})
		return
	}
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
	backend := cfg.Interface.Backend
	if backend == "" {
		backend = "auto"
	}
	protocol := cfg.Interface.Protocol
	if protocol == "" {
		if cfg.Interface.HasAmnezia() {
			protocol = wgbackend.ProtocolAWG
		} else {
			protocol = wgbackend.ProtocolWG
		}
	}
	var amJSON string
	if cfg.Interface.HasAmnezia() {
		amJSON = encodeAmnezia(&pkgapi.AmneziaParams{
			Jc: cfg.Interface.Jc, Jmin: cfg.Interface.Jmin, Jmax: cfg.Interface.Jmax,
			S1: cfg.Interface.S1, S2: cfg.Interface.S2, S3: cfg.Interface.S3, S4: cfg.Interface.S4,
			H1: cfg.Interface.H1, H2: cfg.Interface.H2, H3: cfg.Interface.H3, H4: cfg.Interface.H4,
			I1: cfg.Interface.I1, I2: cfg.Interface.I2, I3: cfg.Interface.I3, I4: cfg.Interface.I4, I5: cfg.Interface.I5,
		})
	}
	iface := &db.Interface{
		Name:        name,
		PrivateKey:  cfg.Interface.PrivateKey,
		PublicKey:   pub,
		ListenPort:  cfg.Interface.ListenPort,
		FwMark:      cfg.Interface.FwMark,
		MTU:         cfg.Interface.MTU,
		TableMode:   tableMode,
		TableID:     tableID,
		DNS:         cfg.Interface.DNS,
		Addresses:   cfg.Interface.Address,
		PreUp:       cfg.Interface.PreUp,
		PostUp:      cfg.Interface.PostUp,
		PreDown:     cfg.Interface.PreDown,
		PostDown:    cfg.Interface.PostDown,
		Enabled:     true,
		Backend:     backend,
		Protocol:    protocol,
		AmneziaJSON: amJSON,
		PairName:    cfg.Interface.PairName,
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
	am := decodeAmnezia(iface.AmneziaJSON)
	sec := confparse.InterfaceSection{
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
		Backend:    iface.Backend,
		Protocol:   iface.Protocol,
		PairName:   iface.PairName,
	}
	if am != nil {
		sec.Jc, sec.Jmin, sec.Jmax = am.Jc, am.Jmin, am.Jmax
		sec.S1, sec.S2, sec.S3, sec.S4 = am.S1, am.S2, am.S3, am.S4
		sec.H1, sec.H2, sec.H3, sec.H4 = am.H1, am.H2, am.H3, am.H4
		sec.I1, sec.I2, sec.I3, sec.I4, sec.I5 = am.I1, am.I2, am.I3, am.I4, am.I5
	}
	cfg := &confparse.Config{
		Interface: sec,
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
	resolved := ""
	if dev, err := s.backend.Device(ctx, iface.Name); err == nil && dev != nil {
		resolved = dev.Backend
	}
	out := pkgapi.Interface{
		ID: iface.ID, Name: iface.Name, PublicKey: iface.PublicKey,
		ListenPort: iface.ListenPort, FwMark: iface.FwMark, MTU: iface.MTU,
		TableMode: iface.TableMode, TableID: iface.TableID, DNS: iface.DNS,
		Addresses: iface.Addresses, DefaultKeepalive: iface.DefaultKeepalive,
		PublicEndpoint: iface.PublicEndpoint,
		Enabled:        iface.Enabled, Up: up, PeerCount: len(peers),
		RxBytes: rx, TxBytes: tx, RxBps: rxBps, TxBps: txBps,
		Backend: iface.Backend, ResolvedBackend: resolved,
		Protocol: iface.Protocol, Amnezia: decodeAmnezia(iface.AmneziaJSON),
		PairName:  iface.PairName,
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
