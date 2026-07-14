package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/reloadlife/wireguardd/internal/stats"
)

// Collector exports WireGuard stats from the cache.
type Collector struct {
	cache      *stats.Cache
	up         prometheus.Gauge
	reconcile  *prometheus.HistogramVec
	reconcileE prometheus.Counter
}

// New registers process-level metrics and returns a collector that scrapes the cache.
func New(cache *stats.Cache, reg prometheus.Registerer) *Collector {
	if reg == nil {
		reg = prometheus.DefaultRegisterer
	}
	c := &Collector{
		cache: cache,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "wireguardd_up",
			Help: "1 if wireguardd is up",
		}),
		reconcile: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "wireguardd_reconcile_duration_seconds",
			Help:    "Reconcile duration",
			Buckets: prometheus.DefBuckets,
		}, []string{}),
		reconcileE: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "wireguardd_reconcile_errors_total",
			Help: "Reconcile errors",
		}),
	}
	c.up.Set(1)
	_ = reg.Register(c.up)
	_ = reg.Register(c.reconcile)
	_ = reg.Register(c.reconcileE)
	_ = reg.Register(newCacheCollector(cache))
	return c
}

// ObserveReconcile records duration and error.
func (c *Collector) ObserveReconcile(d time.Duration, err error) {
	c.reconcile.WithLabelValues().Observe(d.Seconds())
	if err != nil {
		c.reconcileE.Inc()
	}
}

type cacheCollector struct {
	cache *stats.Cache

	ifaceUp    *prometheus.Desc
	ifacePeers *prometheus.Desc
	ifacePort  *prometheus.Desc
	ifaceRx    *prometheus.Desc
	ifaceTx    *prometheus.Desc
	ifaceRxBps *prometheus.Desc
	ifaceTxBps *prometheus.Desc
	ifaceInfo  *prometheus.Desc

	peerHandshake *prometheus.Desc
	peerAge       *prometheus.Desc
	peerConn      *prometheus.Desc
	peerConnSince *prometheus.Desc
	peerRx        *prometheus.Desc
	peerTx        *prometheus.Desc
	peerRxBps     *prometheus.Desc
	peerTxBps     *prometheus.Desc
	peerRxBpsRaw  *prometheus.Desc
	peerTxBpsRaw  *prometheus.Desc
	peerWinRx     *prometheus.Desc
	peerWinTx     *prometheus.Desc
	peerSusp      *prometheus.Desc
	peerLimit     *prometheus.Desc
	peerBwRx      *prometheus.Desc
	peerBwTx      *prometheus.Desc
	peerInfo      *prometheus.Desc
	peerAllowed   *prometheus.Desc
	peerEndpoint  *prometheus.Desc
}

func newCacheCollector(cache *stats.Cache) *cacheCollector {
	return &cacheCollector{
		cache:      cache,
		ifaceUp:    prometheus.NewDesc("wireguard_interface_up", "Interface operstate", []string{"interface"}, nil),
		ifacePeers: prometheus.NewDesc("wireguard_interface_peers", "Peer count", []string{"interface"}, nil),
		ifacePort:  prometheus.NewDesc("wireguard_interface_listen_port", "Listen port", []string{"interface"}, nil),
		ifaceRx:    prometheus.NewDesc("wireguard_interface_receive_bytes_total", "Interface RX bytes", []string{"interface"}, nil),
		ifaceTx:    prometheus.NewDesc("wireguard_interface_transmit_bytes_total", "Interface TX bytes", []string{"interface"}, nil),
		ifaceRxBps: prometheus.NewDesc("wireguard_interface_receive_bytes_per_second", "Interface RX rate", []string{"interface"}, nil),
		ifaceTxBps: prometheus.NewDesc("wireguard_interface_transmit_bytes_per_second", "Interface TX rate", []string{"interface"}, nil),
		ifaceInfo:  prometheus.NewDesc("wireguard_interface_info", "Interface info", []string{"interface", "public_key"}, nil),

		peerHandshake: prometheus.NewDesc("wireguard_peer_last_handshake_seconds", "Last handshake unix", []string{"interface", "public_key"}, nil),
		peerAge:       prometheus.NewDesc("wireguard_peer_handshake_age_seconds", "Handshake age", []string{"interface", "public_key"}, nil),
		peerConn:      prometheus.NewDesc("wireguard_peer_connected", "Peer connected", []string{"interface", "public_key"}, nil),
		peerConnSince: prometheus.NewDesc("wireguard_peer_connected_since_seconds", "Connected since unix", []string{"interface", "public_key"}, nil),
		peerRx:       prometheus.NewDesc("wireguard_peer_receive_bytes_total", "Peer RX accumulative bytes (since soft-reset)", []string{"interface", "public_key"}, nil),
		peerTx:       prometheus.NewDesc("wireguard_peer_transmit_bytes_total", "Peer TX accumulative bytes (since soft-reset)", []string{"interface", "public_key"}, nil),
		peerRxBps:    prometheus.NewDesc("wireguard_peer_receive_bytes_per_second", "Peer RX EWMA rate (bytes/sec)", []string{"interface", "public_key"}, nil),
		peerTxBps:    prometheus.NewDesc("wireguard_peer_transmit_bytes_per_second", "Peer TX EWMA rate (bytes/sec)", []string{"interface", "public_key"}, nil),
		peerRxBpsRaw: prometheus.NewDesc("wireguard_peer_receive_bytes_per_second_raw", "Peer RX last-interval rate (bytes/sec)", []string{"interface", "public_key"}, nil),
		peerTxBpsRaw: prometheus.NewDesc("wireguard_peer_transmit_bytes_per_second_raw", "Peer TX last-interval rate (bytes/sec)", []string{"interface", "public_key"}, nil),
		peerWinRx:    prometheus.NewDesc("wireguard_peer_receive_bytes_window", "Peer RX bytes over lookback window", []string{"interface", "public_key", "window"}, nil),
		peerWinTx:    prometheus.NewDesc("wireguard_peer_transmit_bytes_window", "Peer TX bytes over lookback window", []string{"interface", "public_key", "window"}, nil),
		peerSusp:     prometheus.NewDesc("wireguard_peer_suspended", "Peer suspended", []string{"interface", "public_key"}, nil),
		peerLimit:     prometheus.NewDesc("wireguard_peer_traffic_limit_bytes", "Traffic limit", []string{"interface", "public_key"}, nil),
		peerBwRx:      prometheus.NewDesc("wireguard_peer_bandwidth_rx_limit_bps", "RX bandwidth limit", []string{"interface", "public_key"}, nil),
		peerBwTx:      prometheus.NewDesc("wireguard_peer_bandwidth_tx_limit_bps", "TX bandwidth limit", []string{"interface", "public_key"}, nil),
		peerInfo:      prometheus.NewDesc("wireguard_peer_info", "Peer info", []string{"interface", "public_key", "name", "endpoint"}, nil),
		peerAllowed:   prometheus.NewDesc("wireguard_peer_allowed_ips", "Allowed IP", []string{"interface", "public_key", "allowed_ip"}, nil),
		peerEndpoint:  prometheus.NewDesc("wireguard_peer_endpoint_info", "Endpoint", []string{"interface", "public_key", "endpoint"}, nil),
	}
}

func (c *cacheCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.ifaceUp, c.ifacePeers, c.ifacePort, c.ifaceRx, c.ifaceTx, c.ifaceRxBps, c.ifaceTxBps, c.ifaceInfo,
		c.peerHandshake, c.peerAge, c.peerConn, c.peerConnSince, c.peerRx, c.peerTx, c.peerRxBps, c.peerTxBps,
		c.peerRxBpsRaw, c.peerTxBpsRaw, c.peerWinRx, c.peerWinTx,
		c.peerSusp, c.peerLimit, c.peerBwRx, c.peerBwTx, c.peerInfo, c.peerAllowed, c.peerEndpoint,
	} {
		ch <- d
	}
}

func (c *cacheCollector) Collect(ch chan<- prometheus.Metric) {
	ifaces, peers := c.cache.Snapshot()
	now := time.Now()
	for _, iface := range ifaces {
		up := 0.0
		if iface.Up {
			up = 1
		}
		ch <- prometheus.MustNewConstMetric(c.ifaceUp, prometheus.GaugeValue, up, iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifacePeers, prometheus.GaugeValue, float64(iface.PeerCount), iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifacePort, prometheus.GaugeValue, float64(iface.ListenPort), iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifaceRx, prometheus.CounterValue, float64(iface.RxBytes), iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifaceTx, prometheus.CounterValue, float64(iface.TxBytes), iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifaceRxBps, prometheus.GaugeValue, iface.RxBps, iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifaceTxBps, prometheus.GaugeValue, iface.TxBps, iface.Name)
		ch <- prometheus.MustNewConstMetric(c.ifaceInfo, prometheus.GaugeValue, 1, iface.Name, iface.PublicKey)
	}
	for _, p := range peers {
		hs := 0.0
		age := 0.0
		if !p.LastHandshake.IsZero() {
			hs = float64(p.LastHandshake.Unix())
			age = now.Sub(p.LastHandshake).Seconds()
		}
		conn := 0.0
		if p.Connected {
			conn = 1
		}
		connSince := 0.0
		if !p.ConnectedSince.IsZero() {
			connSince = float64(p.ConnectedSince.Unix())
		}
		susp := 0.0
		if p.Suspended {
			susp = 1
		}
		labels := []string{p.Interface, p.PublicKey}
		ch <- prometheus.MustNewConstMetric(c.peerHandshake, prometheus.GaugeValue, hs, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerAge, prometheus.GaugeValue, age, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerConn, prometheus.GaugeValue, conn, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerConnSince, prometheus.GaugeValue, connSince, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerRx, prometheus.CounterValue, float64(p.RxBytes), labels...)
		ch <- prometheus.MustNewConstMetric(c.peerTx, prometheus.CounterValue, float64(p.TxBytes), labels...)
		ch <- prometheus.MustNewConstMetric(c.peerRxBps, prometheus.GaugeValue, p.RxBps, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerTxBps, prometheus.GaugeValue, p.TxBps, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerRxBpsRaw, prometheus.GaugeValue, p.RxBpsRaw, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerTxBpsRaw, prometheus.GaugeValue, p.TxBpsRaw, labels...)
		for win, wc := range p.Windows {
			ch <- prometheus.MustNewConstMetric(c.peerWinRx, prometheus.GaugeValue, float64(wc.RxBytes), p.Interface, p.PublicKey, win)
			ch <- prometheus.MustNewConstMetric(c.peerWinTx, prometheus.GaugeValue, float64(wc.TxBytes), p.Interface, p.PublicKey, win)
		}
		ch <- prometheus.MustNewConstMetric(c.peerSusp, prometheus.GaugeValue, susp, labels...)
		ch <- prometheus.MustNewConstMetric(c.peerLimit, prometheus.GaugeValue, float64(p.TrafficLimitBytes), labels...)
		ch <- prometheus.MustNewConstMetric(c.peerBwRx, prometheus.GaugeValue, float64(p.BandwidthRxBps), labels...)
		ch <- prometheus.MustNewConstMetric(c.peerBwTx, prometheus.GaugeValue, float64(p.BandwidthTxBps), labels...)
		ch <- prometheus.MustNewConstMetric(c.peerInfo, prometheus.GaugeValue, 1, p.Interface, p.PublicKey, p.Name, p.Endpoint)
		if p.Endpoint != "" {
			ch <- prometheus.MustNewConstMetric(c.peerEndpoint, prometheus.GaugeValue, 1, p.Interface, p.PublicKey, p.Endpoint)
		}
		for _, a := range p.AllowedIPs {
			ch <- prometheus.MustNewConstMetric(c.peerAllowed, prometheus.GaugeValue, 1, p.Interface, p.PublicKey, a)
		}
	}
}
