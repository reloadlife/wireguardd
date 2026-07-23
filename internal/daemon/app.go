package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/reloadlife/wireguardd/internal/adopt"
	"github.com/reloadlife/wireguardd/internal/api"
	"github.com/reloadlife/wireguardd/internal/config"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/metrics"
	"github.com/reloadlife/wireguardd/internal/reconcile"
	"github.com/reloadlife/wireguardd/internal/snmp"
	"github.com/reloadlife/wireguardd/internal/stats"
	"github.com/reloadlife/wireguardd/internal/version"
	"github.com/reloadlife/wireguardd/internal/webhook"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

// App is the wireguardd process.
type App struct {
	cfg *config.DaemonConfig
	log *slog.Logger
}

// New creates an App.
func New(cfg *config.DaemonConfig, log *slog.Logger) *App {
	if log == nil {
		log = slog.Default()
	}
	return &App{cfg: cfg, log: log}
}

// Run starts the daemon until signal.
func (a *App) Run(ctx context.Context) error {
	store, err := db.OpenWithOptions(db.OpenOptions{
		Path:           a.cfg.DB.Path,
		TimeseriesPath: a.cfg.DB.TimeseriesPath,
	})
	if err != nil {
		return fmt.Errorf("open db: %w", err)
	}
	defer func() { _ = store.Close() }()
	a.log.Info("sqlite open",
		"state", a.cfg.DB.Path,
		"timeseries", store.TimeseriesPath(),
	)

	var backend wgbackend.Backend
	if a.cfg.WireGuard.UseMockBackend {
		a.log.Warn("using mock wireguard backend (explicit use_mock_backend)")
		backend = wgbackend.NewMock()
	} else {
		hb, err := wgbackend.NewHostBackend(wgbackend.HostOptions{
			ConfDir:          a.cfg.WireGuard.ConfDir,
			AllowHooks:       a.cfg.WireGuard.AllowHooks,
			BandwidthBackend: a.cfg.WireGuard.BandwidthBackend,
			DNSBackend:       a.cfg.WireGuard.DNSBackend,
			WireGuardGo:      a.cfg.WireGuard.WireGuardGo,
			AmneziaWGGo:      a.cfg.WireGuard.AmneziaWGGo,
			AWGTool:          a.cfg.WireGuard.AWGTool,
		})
		if err != nil {
			return fmt.Errorf("open wireguard backend (set wireguard.use_mock_backend: true for airgap/dev): %w", err)
		}
		backend = hb
	}
	defer func() { _ = backend.Close() }()

	cache := stats.NewCache()
	collector := metrics.New(cache, nil)

	// Optional controller webhooks (also receives all store.AddEvent kinds).
	wh := webhook.New(webhook.Config{
		Enabled:   a.cfg.Webhooks.Enabled,
		URL:       a.cfg.Webhooks.URL,
		Secret:    a.cfg.Webhooks.Secret,
		Events:    a.cfg.Webhooks.Events,
		Timeout:   a.cfg.Webhooks.Timeout,
		QueueSize: a.cfg.Webhooks.QueueSize,
	}, "wireguardd", version.Version, a.log)
	store.SetEventHook(func(level, kind, iface, peerKey, message, meta string) {
		wh.EmitFromStore(level, kind, iface, peerKey, message, meta)
	})

	rec := reconcile.New(store, backend, cache, reconcile.Config{
		Persistence:           a.cfg.WireGuard.Persistence,
		ConfDir:               a.cfg.WireGuard.ConfDir,
		HandshakeConnectedSec: a.cfg.WireGuard.HandshakeConnectedSec,
		SampleInterval:        a.cfg.SampleInterval(),
		AllowHooks:            a.cfg.WireGuard.AllowHooks,
	}, a.log)
	rec.SetMetrics(collector)

	// Attach to already-running host WireGuard (DB empty → import live devices).
	if a.cfg.WireGuard.AdoptOnStart {
		svc := adopt.New(store, backend, a.cfg.WireGuard.ConfDir, a.log)
		rep, err := svc.Adopt(ctx, adopt.Options{ReadConf: true, Overwrite: false})
		if err != nil {
			a.log.Error("adopt_on_start failed", "err", err)
		} else {
			for _, r := range rep.Results {
				a.log.Info("adopt_on_start",
					"iface", r.Name, "action", r.Action,
					"peers", r.PeerCount, "has_private_key", r.HasPrivateKey,
					"conf_loaded", r.ConfLoaded)
			}
		}
	}

	srvAPI := api.NewServer(store, backend, cache, rec, a.cfg, a.log)
	handler := srvAPI.Router()

	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	wh.Start(ctx)
	defer wh.Close()

	go rec.Loop(ctx, a.cfg.ReconcileInterval())

	var servers []*http.Server
	errCh := make(chan error, 4)

	// HTTP API
	if a.cfg.Listen.HTTP != "" {
		ln, err := net.Listen("tcp", a.cfg.Listen.HTTP)
		if err != nil {
			return fmt.Errorf("listen http: %w", err)
		}
		s := &http.Server{Handler: handler}
		servers = append(servers, s)
		a.log.Info("http api listening", "addr", a.cfg.Listen.HTTP)
		go func() { errCh <- s.Serve(ln) }()
	}

	// Unix socket
	if a.cfg.Listen.Unix != "" {
		if err := os.MkdirAll(filepath.Dir(a.cfg.Listen.Unix), 0o755); err != nil {
			return err
		}
		_ = os.Remove(a.cfg.Listen.Unix)
		ln, err := net.Listen("unix", a.cfg.Listen.Unix)
		if err != nil {
			return fmt.Errorf("listen unix: %w", err)
		}
		_ = os.Chmod(a.cfg.Listen.Unix, 0o660)
		s := &http.Server{Handler: handler}
		servers = append(servers, s)
		a.log.Info("unix api listening", "path", a.cfg.Listen.Unix)
		go func() { errCh <- s.Serve(ln) }()
	}

	// Dedicated metrics listener
	if a.cfg.Listen.Metrics != "" && a.cfg.Listen.Metrics != a.cfg.Listen.HTTP {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		ln, err := net.Listen("tcp", a.cfg.Listen.Metrics)
		if err != nil {
			return fmt.Errorf("listen metrics: %w", err)
		}
		s := &http.Server{Handler: mux}
		servers = append(servers, s)
		a.log.Info("metrics listening", "addr", a.cfg.Listen.Metrics)
		go func() { errCh <- s.Serve(ln) }()
	}

	var snmpAgent *snmp.Agent
	if a.cfg.SNMP.Enabled {
		snmpAgent = snmp.NewAgent(a.cfg.SNMP.Listen, a.cfg.SNMP.Community, a.cfg.SNMP.EnterpriseOID, cache, a.log)
		if err := snmpAgent.Start(); err != nil {
			a.log.Error("snmp start failed", "err", err)
		} else {
			defer func() { _ = snmpAgent.Close() }()
		}
	}

	select {
	case <-ctx.Done():
		a.log.Info("shutting down")
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			return err
		}
	}

	shutdownCtx, c := context.WithTimeout(context.Background(), 10*time.Second)
	defer c()
	for _, s := range servers {
		_ = s.Shutdown(shutdownCtx)
	}
	return nil
}
