package tui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"

	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func TestRootModelTabs(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.ifaces = []pkgapi.Interface{{Name: "wg0", Up: true, ListenPort: 51820}}
	m.peers = []pkgapi.Peer{{InterfaceName: "wg0", Name: "a", PublicKey: "x"}}
	view := m.View()
	require.Contains(t, view, "Interfaces")

	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("2")})
	m = nm.(rootModel)
	require.Equal(t, tabPeers, m.tab)
	require.Contains(t, m.View(), "Peers")
}

func TestFormatHelpers(t *testing.T) {
	require.Equal(t, "500 B", formatBytes(500))
	require.Contains(t, formatBytes(1500), "KB")
	require.Contains(t, formatBps(1500), "KB")
}
