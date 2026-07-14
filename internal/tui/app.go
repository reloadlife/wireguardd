package tui

import (
	"context"
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

// Config for the TUI.
type Config struct {
	Client          *pkgapi.Client
	Endpoint        string
	RefreshInterval time.Duration
}

// Run starts the Bubble Tea program.
func Run(cfg Config) error {
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 2 * time.Second
	}
	m := newRootModel(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}

type tickMsg time.Time

type dataMsg struct {
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

func fetchData(c *pkgapi.Client) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var msg dataMsg
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

func doSuspend(c *pkgapi.Client, iface, pub string, suspend bool) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var err error
		if suspend {
			err = c.SuspendPeer(ctx, iface, pub)
		} else {
			err = c.ResumePeer(ctx, iface, pub)
		}
		if err != nil {
			return dataMsg{err: err}
		}
		return fetchData(c)()
	}
}

func doIfaceUpDown(c *pkgapi.Client, name string, up bool) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var err error
		if up {
			err = c.InterfaceUp(ctx, name)
		} else {
			err = c.InterfaceDown(ctx, name)
		}
		if err != nil {
			return dataMsg{err: err}
		}
		return fetchData(c)()
	}
}

func doDeleteIface(c *pkgapi.Client, name string) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := c.DeleteInterface(ctx, name); err != nil {
			return dataMsg{err: err}
		}
		return fetchData(c)()
	}
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
