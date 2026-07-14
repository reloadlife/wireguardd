package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
	"github.com/reloadlife/wireguardd/pkg/wgutil"
)

const (
	tabInterfaces = 0
	tabPeers      = 1
	tabStats      = 2
	tabEvents     = 3
	tabKeys       = 4
)

type rootModel struct {
	cfg      Config
	tab      int
	width    int
	height   int
	ifaces   []pkgapi.Interface
	peers    []pkgapi.Peer
	stats    *pkgapi.StatsSummary
	events   []pkgapi.Event
	cursor   int
	err      string
	status   string
	lastKeys *pkgapi.KeyGenerateResponse
	confirm  string // non-empty = pending delete iface name
}

func newRootModel(cfg Config) rootModel {
	return rootModel{cfg: cfg, status: "connecting…"}
}

func (m rootModel) Init() tea.Cmd {
	return tea.Batch(fetchData(m.cfg.Client), tickCmd(m.cfg.RefreshInterval))
}

func tickCmd(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return tickMsg(t) })
}

func (m rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case tickMsg:
		return m, tea.Batch(fetchData(m.cfg.Client), tickCmd(m.cfg.RefreshInterval))
	case dataMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
			m.status = "error"
		} else {
			m.err = ""
			m.ifaces = msg.ifaces
			m.peers = msg.peers
			m.stats = msg.stats
			m.events = msg.events
			m.status = "ok"
			if m.cursor >= m.rowCount() {
				m.cursor = max(0, m.rowCount()-1)
			}
		}
	case keysMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.lastKeys = msg.keys
			m.err = ""
		}
	case tea.KeyMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

func (m rootModel) rowCount() int {
	switch m.tab {
	case tabInterfaces:
		return len(m.ifaces)
	case tabPeers:
		return len(m.peers)
	case tabEvents:
		return len(m.events)
	default:
		return 0
	}
}

func (m rootModel) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.confirm != "" {
		switch msg.String() {
		case "y", "Y":
			name := m.confirm
			m.confirm = ""
			return m, doDeleteIface(m.cfg.Client, name)
		case "n", "N", "esc":
			m.confirm = ""
		}
		return m, nil
	}

	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "1":
		m.tab = tabInterfaces
		m.cursor = 0
	case "2":
		m.tab = tabPeers
		m.cursor = 0
	case "3":
		m.tab = tabStats
		m.cursor = 0
	case "4":
		m.tab = tabEvents
		m.cursor = 0
	case "5":
		m.tab = tabKeys
		m.cursor = 0
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % 5
		m.cursor = 0
	case "shift+tab", "left", "h":
		m.tab = (m.tab + 4) % 5
		m.cursor = 0
	case "j", "down":
		if m.cursor < m.rowCount()-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "r":
		return m, fetchData(m.cfg.Client)
	case "u":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			return m, doIfaceUpDown(m.cfg.Client, m.ifaces[m.cursor].Name, true)
		}
	case "d":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			return m, doIfaceUpDown(m.cfg.Client, m.ifaces[m.cursor].Name, false)
		}
	case "D":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			m.confirm = m.ifaces[m.cursor].Name
		}
	case "s":
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			p := m.peers[m.cursor]
			return m, doSuspend(m.cfg.Client, p.InterfaceName, p.PublicKey, !p.Suspended)
		}
	case "g":
		if m.tab == tabKeys {
			return m, doGenerateKeys(m.cfg.Client, "keypair")
		}
	case "p":
		if m.tab == tabKeys {
			return m, doGenerateKeys(m.cfg.Client, "preshared")
		}
	}
	return m, nil
}

func (m rootModel) View() string {
	var b strings.Builder
	b.WriteString(statusStyle.Render(fmt.Sprintf(" wireguardctl · %s · %s ", m.cfg.Endpoint, m.status)))
	b.WriteString("\n")
	b.WriteString(m.renderTabs())
	b.WriteString("\n\n")

	if m.confirm != "" {
		b.WriteString(errStyle.Render(fmt.Sprintf("Delete interface %s? [y/N]", m.confirm)))
		b.WriteString("\n")
	}
	if m.err != "" {
		b.WriteString(errStyle.Render("error: " + m.err))
		b.WriteString("\n\n")
	}

	switch m.tab {
	case tabInterfaces:
		b.WriteString(m.viewInterfaces())
	case tabPeers:
		b.WriteString(m.viewPeers())
	case tabStats:
		b.WriteString(m.viewStats())
	case tabEvents:
		b.WriteString(m.viewEvents())
	case tabKeys:
		b.WriteString(m.viewKeys())
	}

	b.WriteString("\n")
	b.WriteString(helpStyle.Render("1-5 tabs · j/k move · r refresh · u/d iface up/down · D delete · s suspend · g/p keys · q quit"))
	return b.String()
}

func (m rootModel) renderTabs() string {
	names := []string{"Interfaces", "Peers", "Stats", "Events", "Keys"}
	parts := make([]string, len(names))
	for i, n := range names {
		label := fmt.Sprintf("%d %s", i+1, n)
		if i == m.tab {
			parts[i] = tabActive.Render(label)
		} else {
			parts[i] = tabInactive.Render(label)
		}
	}
	return lipgloss.JoinHorizontal(lipgloss.Top, parts...)
}

func (m rootModel) viewInterfaces() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-10s %-6s %6s %6s %10s %10s %8s", "NAME", "STATE", "PORT", "PEERS", "RX/s", "TX/s", "RX")))
	b.WriteString("\n")
	for i, iface := range m.ifaces {
		state := "DOWN"
		if iface.Up {
			state = "UP"
		}
		line := fmt.Sprintf("%-10s %-6s %6d %6d %10s %10s %8s",
			iface.Name, state, iface.ListenPort, iface.PeerCount,
			formatBps(iface.RxBps), formatBps(iface.TxBps), formatBytes(iface.RxBytes))
		if i == m.cursor {
			line = tabActive.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.ifaces) == 0 {
		b.WriteString(helpStyle.Render("(no interfaces — use wireguardctl iface create)"))
	}
	return b.String()
}

func (m rootModel) viewPeers() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-8s %-12s %-10s %-8s %10s %10s %s", "IFACE", "NAME", "PUBKEY", "STATE", "RX/s", "TX", "ENDPOINT")))
	b.WriteString("\n")
	for i, p := range m.peers {
		state := "ok"
		if p.Suspended {
			state = "SUSP"
		} else if p.Connected {
			state = "conn"
		}
		line := fmt.Sprintf("%-8s %-12s %-10s %-8s %10s %10s %s",
			p.InterfaceName, trunc(p.Name, 12), wgutil.ShortKey(p.PublicKey), state,
			formatBps(p.RxBps), formatBytes(p.RxBytes+p.TxBytes), trunc(p.LastEndpoint, 24))
		if i == m.cursor {
			line = tabActive.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.peers) == 0 {
		b.WriteString(helpStyle.Render("(no peers)"))
	}
	return b.String()
}

func (m rootModel) viewStats() string {
	if m.stats == nil {
		return helpStyle.Render("no stats yet")
	}
	s := m.stats
	return fmt.Sprintf(
		"Interfaces: %d\nPeers:      %d\nConnected:  %d\nSuspended:  %d\nRX total:   %s  (%s)\nTX total:   %s  (%s)\n",
		s.Interfaces, s.Peers, s.Connected, s.Suspended,
		formatBytes(s.RxBytes), formatBps(s.RxBps),
		formatBytes(s.TxBytes), formatBps(s.TxBps),
	)
}

func (m rootModel) viewEvents() string {
	var b strings.Builder
	for i, e := range m.events {
		if i >= 30 {
			break
		}
		line := fmt.Sprintf("%s [%s/%s] %s %s",
			e.TS.Format("15:04:05"), e.Level, e.Kind, e.Interface, e.Message)
		if i == m.cursor {
			line = tabActive.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.events) == 0 {
		b.WriteString(helpStyle.Render("(no events)"))
	}
	return b.String()
}

func (m rootModel) viewKeys() string {
	var b strings.Builder
	b.WriteString("Press g to generate keypair, p for preshared key.\n\n")
	if m.lastKeys != nil {
		if m.lastKeys.PrivateKey != "" {
			b.WriteString("PrivateKey:  " + m.lastKeys.PrivateKey + "\n")
			b.WriteString("PublicKey:   " + m.lastKeys.PublicKey + "\n")
		}
		if m.lastKeys.PresharedKey != "" {
			b.WriteString("PresharedKey: " + m.lastKeys.PresharedKey + "\n")
		}
	}
	return b.String()
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
