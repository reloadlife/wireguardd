package tui

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

type tickMsg time.Time

type flashClearMsg struct {
	id int
}

type dataMsg struct {
	gen    uint64
	ifaces []pkgapi.Interface
	peers  []pkgapi.Peer
	stats  *pkgapi.StatsSummary
	events []pkgapi.Event
	err    error
}

type keysMsg struct {
	keys *pkgapi.KeyGenerateResponse
	err  error
}

type actionDoneMsg struct {
	err     error
	flash   string
	refresh bool
}

type clientConfMsg struct {
	config string
	qr     string // terminal QR (optional)
	err    error
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func flashClearCmd(id int) tea.Cmd {
	return tea.Tick(3*time.Second, func(t time.Time) tea.Msg { return flashClearMsg{id: id} })
}

func fetchData(c *pkgapi.Client, gen uint64) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var msg dataMsg
		msg.gen = gen
		ifaces, err := c.ListInterfaces(ctx)
		if err != nil {
			msg.err = err
			return msg
		}
		msg.ifaces = ifaces
		peers, err := c.ListAllPeers(ctx)
		if err != nil {
			msg.err = err
			return msg
		}
		msg.peers = peers
		stats, err := c.Stats(ctx)
		if err != nil {
			msg.err = err
			return msg
		}
		msg.stats = stats
		events, err := c.ListEvents(ctx)
		if err != nil {
			msg.err = err
			return msg
		}
		msg.events = events
		return msg
	}
}

func doGenerateKeys(c *pkgapi.Client, typ string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		k, err := c.GenerateKeys(ctx, typ)
		return keysMsg{keys: k, err: err}
	}
}

func doAction(fn func(ctx context.Context) error, flash string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := fn(ctx)
		return actionDoneMsg{err: err, flash: flash, refresh: err == nil}
	}
}

func doSuspend(c *pkgapi.Client, iface, pub string, suspend bool) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		if suspend {
			return c.SuspendPeer(ctx, iface, pub)
		}
		return c.ResumePeer(ctx, iface, pub)
	}, map[bool]string{true: "peer suspended", false: "peer resumed"}[suspend])
}

func doIfaceUpDown(c *pkgapi.Client, name string, up bool) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		if up {
			return c.InterfaceUp(ctx, name)
		}
		return c.InterfaceDown(ctx, name)
	}, map[bool]string{true: name + " up", false: name + " down"}[up])
}

func doDeleteIface(c *pkgapi.Client, name string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeleteInterface(ctx, name)
	}, "deleted interface "+name)
}

func doDeletePeer(c *pkgapi.Client, iface, pub string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.DeletePeer(ctx, iface, pub)
	}, "deleted peer")
}

func doResetTraffic(c *pkgapi.Client, iface, pub string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.ResetPeerTraffic(ctx, iface, pub)
	}, "traffic counters reset")
}

func doCreateIface(c *pkgapi.Client, req pkgapi.InterfaceCreateRequest) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreateInterface(ctx, req)
		return err
	}, "interface "+req.Name+" created")
}

func doUpdateIface(c *pkgapi.Client, name string, req pkgapi.InterfaceUpdateRequest) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.UpdateInterface(ctx, name, req)
		return err
	}, "interface "+name+" updated")
}

func doCreatePeer(c *pkgapi.Client, iface string, req pkgapi.PeerCreateRequest) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.CreatePeer(ctx, iface, req)
		return err
	}, "peer created")
}

func doUpdatePeer(c *pkgapi.Client, iface, pub string, req pkgapi.PeerUpdateRequest) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		_, err := c.UpdatePeer(ctx, iface, pub, req)
		return err
	}, "peer updated")
}

func doFetchClientConf(c *pkgapi.Client, iface, pub string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cfg, err := c.PeerClientConfig(ctx, iface, pub)
		if err != nil {
			return clientConfMsg{err: err}
		}
		qr, qerr := RenderQR(cfg)
		if qerr != nil {
			// still show conf even if QR fails
			return clientConfMsg{config: cfg, err: nil}
		}
		return clientConfMsg{config: cfg, qr: qr}
	}
}

func doExportIface(c *pkgapi.Client, name string) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.ExportInterface(ctx, name)
	}, "exported "+name+" conf")
}

func doReconcile(c *pkgapi.Client) tea.Cmd {
	return doAction(func(ctx context.Context) error {
		return c.Reconcile(ctx)
	}, "reconcile complete")
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseIntField(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	return strconv.Atoi(s)
}

func parseInt64Field(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

func joinCSV(ss []string) string {
	return strings.Join(ss, ", ")
}

func formatBps(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.1f GB/s", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1f MB/s", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.1f KB/s", v/1e3)
	default:
		return fmt.Sprintf("%.0f B/s", v)
	}
}

func formatBytes(v int64) string {
	f := float64(v)
	switch {
	case f >= 1e12:
		return fmt.Sprintf("%.1f TB", f/1e12)
	case f >= 1e9:
		return fmt.Sprintf("%.1f GB", f/1e9)
	case f >= 1e6:
		return fmt.Sprintf("%.1f MB", f/1e6)
	case f >= 1e3:
		return fmt.Sprintf("%.1f KB", f/1e3)
	default:
		return fmt.Sprintf("%d B", v)
	}
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
