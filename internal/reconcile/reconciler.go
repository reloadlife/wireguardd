package reconcile

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"
	"time"

	"github.com/reloadlife/wireguardd/internal/confparse"
	"github.com/reloadlife/wireguardd/internal/db"
	"github.com/reloadlife/wireguardd/internal/policy"
	"github.com/reloadlife/wireguardd/internal/stats"
	"github.com/reloadlife/wireguardd/internal/wgbackend"
)

// Config for the reconciler.
type Config struct {
	Persistence           string // database | wg-quick | hybrid
	ConfDir               string
	HandshakeConnectedSec int
	SampleInterval        time.Duration
	AllowHooks            bool
}

// Reconciler applies desired state and samples stats.
type Reconciler struct {
	store  *db.Store
	backend wgbackend.Backend
	cache  *stats.Cache
	cfg    Config
	log    *slog.Logger

	mu       sync.Mutex
	prevSample map[string]stats.Sample // peer id key iface/pub
	lastErr  error
}

// New creates a reconciler.
func New(store *db.Store, backend wgbackend.Backend, cache *stats.Cache, cfg Config, log *slog.Logger) *Reconciler {
	if cfg.HandshakeConnectedSec <= 0 {
		cfg.HandshakeConnectedSec = 180
	}
	if log == nil {
		log = slog.Default()
	}
	return &Reconciler{
		store:      store,
		backend:    backend,
		cache:      cache,
		cfg:        cfg,
		log:        log,
		prevSample: make(map[string]stats.Sample),
	}
}

// LastError returns the last reconcile error.
func (r *Reconciler) LastError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastErr
}

// RunOnce performs one full reconcile + sample cycle.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	err := r.run(ctx)
	r.lastErr = err
	return err
}

func (r *Reconciler) run(ctx context.Context) error {
	ifaces, err := r.store.ListInterfaces(ctx)
	if err != nil {
		return err
	}
	live, _ := r.backend.Devices(ctx)
	liveNames := map[string]struct{}{}
	for _, d := range live {
		liveNames[d.Name] = struct{}{}
	}
	desiredNames := map[string]struct{}{}

	for i := range ifaces {
		iface := ifaces[i]
		desiredNames[iface.Name] = struct{}{}
		peers, err := r.store.ListPeersByInterface(ctx, iface.Name)
		if err != nil {
			return err
		}

		// Auto-suspend on traffic limits
		for j := range peers {
			if policy.ShouldAutoSuspend(peers[j]) {
				peers[j].Suspended = true
				_ = r.store.SetPeerSuspended(ctx, peers[j].ID, true)
				_ = r.store.AddEvent(ctx, "warn", "enforce", iface.Name, peers[j].PublicKey,
					"auto-suspended: traffic limit exceeded", "{}")
				r.log.Warn("peer auto-suspended", "iface", iface.Name, "peer", peers[j].PublicKey)
			}
		}

		desiredPeers := make([]wgbackend.DesiredPeer, 0, len(peers))
		for _, p := range peers {
			desiredPeers = append(desiredPeers, wgbackend.DesiredPeer{
				PublicKey:           p.PublicKey,
				PresharedKey:        p.PresharedKey,
				Endpoint:            p.Endpoint,
				AllowedIPs:          p.AllowedIPs,
				AssignedIPs:         p.AssignedIPs,
				PersistentKeepalive: p.PersistentKeepalive,
				Suspended:           p.Suspended,
				BandwidthRxBps:      p.BandwidthRxBps,
				BandwidthTxBps:      p.BandwidthTxBps,
			})
		}

		di := wgbackend.DesiredInterface{
			Name:       iface.Name,
			PrivateKey: iface.PrivateKey,
			ListenPort: iface.ListenPort,
			FwMark:     iface.FwMark,
			MTU:        iface.MTU,
			Addresses:  iface.Addresses,
			TableMode:  iface.TableMode,
			TableID:    iface.TableID,
			DNS:        iface.DNS,
			PreUp:      iface.PreUp,
			PostUp:     iface.PostUp,
			PreDown:    iface.PreDown,
			PostDown:   iface.PostDown,
			Enabled:    iface.Enabled,
			Peers:      desiredPeers,
		}

		if r.cfg.AllowHooks && iface.PreUp != "" {
			_ = r.backend.RunHook(ctx, iface.PreUp)
		}
		if err := r.backend.EnsureInterface(ctx, di); err != nil {
			r.log.Error("ensure interface", "iface", iface.Name, "err", err)
			continue
		}
		if err := r.backend.ApplyPeers(ctx, iface.Name, desiredPeers); err != nil {
			r.log.Error("apply peers", "iface", iface.Name, "err", err)
		}
		for _, p := range desiredPeers {
			_ = r.backend.ApplySuspendRoutes(ctx, iface.Name, p, p.Suspended)
			_ = r.backend.ApplyBandwidth(ctx, iface.Name, p)
		}
		if err := r.backend.SetUp(ctx, iface.Name, iface.Enabled); err != nil {
			r.log.Error("set up", "iface", iface.Name, "err", err)
		}
		if r.cfg.AllowHooks && iface.PostUp != "" && iface.Enabled {
			_ = r.backend.RunHook(ctx, iface.PostUp)
		}

		if r.cfg.Persistence == "hybrid" || r.cfg.Persistence == "wg-quick" {
			if err := r.exportConf(ctx, &iface, peers); err != nil {
				r.log.Error("export conf", "iface", iface.Name, "err", err)
			}
		}

		// Sample live stats
		if err := r.sampleInterface(ctx, &iface, peers); err != nil {
			r.log.Debug("sample", "iface", iface.Name, "err", err)
		}
	}

	// Remove live devices not in desired set (only those we manage — names in DB history)
	// We only delete if it was previously managed: skip orphan kernel devices.
	_ = liveNames
	_ = desiredNames

	// Purge old samples occasionally
	_, _ = r.store.PurgeSamples(ctx, 24*time.Hour)
	return nil
}

func (r *Reconciler) exportConf(ctx context.Context, iface *db.Interface, peers []db.Peer) error {
	cfg := &confparse.Config{
		Interface: confparse.InterfaceSection{
			PrivateKey: iface.PrivateKey,
			Address:    iface.Addresses,
			ListenPort: iface.ListenPort,
			DNS:        iface.DNS,
			MTU:        iface.MTU,
			Table:      iface.TableMode,
			FwMark:     iface.FwMark,
			PreUp:      iface.PreUp,
			PostUp:     iface.PostUp,
			PreDown:    iface.PreDown,
			PostDown:   iface.PostDown,
		},
	}
	if iface.TableMode == "number" && iface.TableID != nil {
		cfg.Interface.Table = fmt.Sprintf("%d", *iface.TableID)
	}
	for _, p := range peers {
		if p.Suspended {
			// still export desired AllowedIPs for persistence of intent
		}
		cfg.Peers = append(cfg.Peers, confparse.PeerSection{
			PublicKey:           p.PublicKey,
			PresharedKey:        p.PresharedKey,
			AllowedIPs:          p.AllowedIPs,
			Endpoint:            p.Endpoint,
			PersistentKeepalive: p.PersistentKeepalive,
		})
	}
	content := confparse.Render(cfg)
	path := filepath.Join(r.cfg.ConfDir, iface.Name+".conf")
	return r.backend.ExportConf(ctx, path, content)
}

func (r *Reconciler) sampleInterface(ctx context.Context, iface *db.Interface, peers []db.Peer) error {
	dev, err := r.backend.Device(ctx, iface.Name)
	if err != nil {
		// Device may not exist yet on mock/host without privileges
		r.cache.SetInterface(stats.IfaceStats{
			Name:       iface.Name,
			PublicKey:  iface.PublicKey,
			Up:         iface.Enabled,
			ListenPort: iface.ListenPort,
			PeerCount:  len(peers),
			UpdatedAt:  time.Now().UTC(),
		})
		return err
	}
	liveByPub := map[string]wgbackend.Peer{}
	for _, lp := range dev.Peers {
		liveByPub[lp.PublicKey] = lp
	}

	now := time.Now().UTC()
	var sumRx, sumTx int64
	var sumRxBps, sumTxBps float64

	for i := range peers {
		p := &peers[i]
		lp, ok := liveByPub[p.PublicKey]
		var rx, tx int64
		var hs time.Time
		ep := p.Endpoint
		if ok {
			rx, tx = lp.ReceiveBytes, lp.TransmitBytes
			hs = lp.LastHandshakeTime
			if lp.Endpoint != "" {
				ep = lp.Endpoint
			}
		}

		key := iface.Name + "/" + p.PublicKey
		cur := stats.Sample{Time: now, Rx: rx, Tx: tx}
		var rxBps, txBps float64
		if prev, ok := r.prevSample[key]; ok {
			rate := stats.ComputeRate(prev, cur)
			rxBps = stats.EWMA(p.LastRxBps, rate.RxBps, 0.3)
			txBps = stats.EWMA(p.LastTxBps, rate.TxBps, 0.3)
		}
		r.prevSample[key] = cur

		p.LastRxBytes = rx
		p.LastTxBytes = tx
		p.LastRxBps = rxBps
		p.LastTxBps = txBps
		p.LastEndpoint = ep

		connected := false
		if !hs.IsZero() {
			hsStr := hs.UTC().Format(time.RFC3339Nano)
			if p.FirstHandshakeAt == "" {
				p.FirstHandshakeAt = hsStr
			}
			p.LastHandshakeAt = hsStr
			if now.Sub(hs) <= time.Duration(r.cfg.HandshakeConnectedSec)*time.Second {
				connected = true
				if p.ConnectedSince == "" {
					p.ConnectedSince = hsStr
				}
			} else {
				p.ConnectedSince = ""
			}
		}

		_ = r.store.UpdatePeerStats(ctx, p)
		_ = r.store.InsertSample(ctx, db.TrafficSample{
			PeerID:    p.ID,
			SampledAt: now,
			RxBytes:   p.EffectiveRx(),
			TxBytes:   p.EffectiveTx(),
			RxBps:     rxBps,
			TxBps:     txBps,
		})

		var connSince time.Time
		if p.ConnectedSince != "" {
			connSince, _ = time.Parse(time.RFC3339Nano, p.ConnectedSince)
		}
		r.cache.SetPeer(stats.PeerStats{
			Interface:         iface.Name,
			PublicKey:         p.PublicKey,
			Name:              p.Name,
			Endpoint:          ep,
			AllowedIPs:        p.AllowedIPs,
			LastHandshake:     hs,
			Connected:         connected,
			ConnectedSince:    connSince,
			RxBytes:           p.EffectiveRx(),
			TxBytes:           p.EffectiveTx(),
			RxBps:             rxBps,
			TxBps:             txBps,
			Suspended:         p.Suspended,
			TrafficLimitBytes: p.TrafficLimitBytes,
			BandwidthRxBps:    p.BandwidthRxBps,
			BandwidthTxBps:    p.BandwidthTxBps,
			UpdatedAt:         now,
		})
		sumRx += p.EffectiveRx()
		sumTx += p.EffectiveTx()
		sumRxBps += rxBps
		sumTxBps += txBps
	}

	r.cache.SetInterface(stats.IfaceStats{
		Name:       iface.Name,
		PublicKey:  iface.PublicKey,
		Up:         dev.Up && iface.Enabled,
		ListenPort: dev.ListenPort,
		PeerCount:  len(peers),
		RxBytes:    sumRx,
		TxBytes:    sumTx,
		RxBps:      sumRxBps,
		TxBps:      sumTxBps,
		UpdatedAt:  now,
	})
	return nil
}

// Loop runs until context cancellation.
func (r *Reconciler) Loop(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	_ = r.RunOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := r.RunOnce(ctx); err != nil {
				r.log.Error("reconcile", "err", err)
			}
		}
	}
}
