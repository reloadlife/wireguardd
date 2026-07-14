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

func TestOpenIfaceCreateForm(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	nm, _ := m.openIfaceCreate()
	m = nm.(rootModel)
	require.Equal(t, modeIfaceForm, m.mode)
	require.True(t, m.formCreate)
	require.Contains(t, m.View(), "New interface")
}

func TestOpenPeerCreateForm(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	nm, _ := m.openPeerCreate("wg0")
	m = nm.(rootModel)
	require.Equal(t, modePeerForm, m.mode)
	require.Equal(t, "wg0", m.form.Get("iface"))
}

func TestEnterIfaceDetail(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.ifaces = []pkgapi.Interface{{Name: "wg0", Up: true, ListenPort: 51820, PublicKey: "pk"}}
	m.tab = tabInterfaces
	m.cursor = 0
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(rootModel)
	require.Equal(t, modeIfaceDetail, m.mode)
	require.Contains(t, m.View(), "Interface wg0")
}

func TestEnterPeerDetail(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.peers = []pkgapi.Peer{{InterfaceName: "wg0", Name: "alice", PublicKey: "pubkey=="}}
	m.tab = tabPeers
	m.cursor = 0
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = nm.(rootModel)
	require.Equal(t, modePeerDetail, m.mode)
	require.Contains(t, m.View(), "alice")
}

func TestConfirmDelete(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.ifaces = []pkgapi.Interface{{Name: "wg0"}}
	m.tab = tabInterfaces
	nm, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("D")})
	m = nm.(rootModel)
	require.Equal(t, modeConfirm, m.mode)
	require.Contains(t, m.View(), "Delete interface")
	nm, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = nm.(rootModel)
	require.Equal(t, modeList, m.mode)
}

func TestFormatHelpers(t *testing.T) {
	require.Equal(t, "500 B", formatBytes(500))
	require.Contains(t, formatBytes(1500), "KB")
	require.Contains(t, formatBps(1500), "KB")
}

func TestFormValues(t *testing.T) {
	f := newForm("t", ifaceCreateFields(), map[string]string{"name": "wg1", "port": "51821"})
	require.Equal(t, "wg1", f.Get("name"))
	require.Equal(t, "51821", f.Get("port"))
}

func TestTruthy(t *testing.T) {
	require.True(t, truthy("y"))
	require.True(t, truthy("YES"))
	require.False(t, truthy("n"))
}

func TestSplitJoinCSV(t *testing.T) {
	require.Equal(t, []string{"a", "b"}, splitCSV("a, b"))
	require.Equal(t, "a, b", joinCSV([]string{"a", "b"}))
}
