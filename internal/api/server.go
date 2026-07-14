package api

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/reloadlife/wireguardd/internal/config"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/reconcile"
	"github.com/reloadlife/wireguardd/internal/stats"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

// Server is the REST API.
type Server struct {
	store      *db.Store
	backend    wgbackend.Backend
	cache      *stats.Cache
	reconciler *reconcile.Reconciler
	cfg        *config.DaemonConfig
	log        *slog.Logger
	handshake  int
}

// NewServer constructs the API server.
func NewServer(
	store *db.Store,
	backend wgbackend.Backend,
	cache *stats.Cache,
	reconciler *reconcile.Reconciler,
	cfg *config.DaemonConfig,
	log *slog.Logger,
) *Server {
	hs := 180
	if cfg != nil && cfg.WireGuard.HandshakeConnectedSec > 0 {
		hs = cfg.WireGuard.HandshakeConnectedSec
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{
		store:      store,
		backend:    backend,
		cache:      cache,
		reconciler: reconciler,
		cfg:        cfg,
		log:        log,
		handshake:  hs,
	}
}

// Router returns the chi router.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(chimw.RequestID)
	r.Use(chimw.RealIP)
	r.Use(chimw.Recoverer)
	r.Use(chimw.Timeout(60 * time.Second))
	r.Use(requestID)

	r.Get("/healthz", s.handleHealthz)
	r.Get("/readyz", s.handleReadyz)

	// Optional: metrics on same listener if no dedicated metrics addr is preferred by caller.
	r.Handle("/metrics", promhttp.Handler())

	r.Route("/v1", func(r chi.Router) {
		r.Use(bearerAuth(s.cfg.Auth.Token))
		r.Use(readOnlyGuard(s.cfg.ReadOnly))

		r.Get("/version", s.handleVersion)
		r.Get("/config", s.handleConfig)
		r.Post("/reconcile", s.handleReconcile)
		r.Get("/events", s.handleEvents)
		r.Get("/stats", s.handleStats)
		r.Get("/stats/peers", s.handleAllPeers)
		r.Get("/stats/interfaces/{name}", s.handleInterfaceStats)

		r.Post("/keys/generate", s.handleKeysGenerate)

		r.Get("/interfaces", s.handleListInterfaces)
		r.Post("/interfaces", s.handleCreateInterface)
		r.Get("/interfaces/{name}", s.handleGetInterface)
		r.Patch("/interfaces/{name}", s.handleUpdateInterface)
		r.Delete("/interfaces/{name}", s.handleDeleteInterface)
		r.Post("/interfaces/{name}/up", s.handleInterfaceUp)
		r.Post("/interfaces/{name}/down", s.handleInterfaceDown)
		r.Post("/interfaces/{name}/export", s.handleInterfaceExport)
		r.Post("/interfaces/{name}/import", s.handleInterfaceImport)

		r.Get("/interfaces/{name}/peers", s.handleListPeers)
		r.Post("/interfaces/{name}/peers", s.handleCreatePeer)
		r.Get("/interfaces/{name}/peers/{pubkey}", s.handleGetPeer)
		r.Patch("/interfaces/{name}/peers/{pubkey}", s.handleUpdatePeer)
		r.Delete("/interfaces/{name}/peers/{pubkey}", s.handleDeletePeer)
		r.Post("/interfaces/{name}/peers/{pubkey}/suspend", s.handleSuspendPeer)
		r.Post("/interfaces/{name}/peers/{pubkey}/resume", s.handleResumePeer)
		r.Post("/interfaces/{name}/peers/{pubkey}/reset-traffic", s.handleResetPeerTraffic)
		r.Get("/interfaces/{name}/peers/{pubkey}/client-config", s.handlePeerClientConfig)
		r.Get("/interfaces/{name}/peers/{pubkey}/qr", s.handlePeerQR)
	})

	return r
}

// ForceReconcile triggers an immediate reconcile.
func (s *Server) ForceReconcile(ctx context.Context) error {
	if s.reconciler == nil {
		return nil
	}
	return s.reconciler.RunOnce(ctx)
}
