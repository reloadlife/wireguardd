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
	m.ifaces = []pkgapi.Interface{{Name: "wg0", Addresses: []string{"10.7.0.1/24"}}}
	nm, _ := m.openPeerCreate("wg0")
	m = nm.(rootModel)
	require.Equal(t, modePeerForm, m.mode)
	require.Equal(t, "wg0", m.form.Get("iface"))
	require.Equal(t, "y", m.form.Get("auto_ip"))
}

func TestResolvePeerIPsAuto(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.ifaces = []pkgapi.Interface{{Name: "wg0", Addresses: []string{"10.7.0.1/24"}}}
	m.peers = []pkgapi.Peer{{InterfaceName: "wg0", AssignedIPs: []string{"10.7.0.2"}, AllowedIPs: []string{"10.7.0.2/32"}}}
	allowed, assigned, err := m.resolvePeerIPs("wg0", map[string]string{"auto_ip": "y"})
	require.NoError(t, err)
	require.Equal(t, []string{"10.7.0.3"}, assigned)
	require.Equal(t, []string{"10.7.0.3/32"}, allowed)
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

func TestStaleDataMsgIgnored(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.fetchGen = 2
	m.ifaces = []pkgapi.Interface{{Name: "keep"}}
	nm, _ := m.Update(dataMsg{
		gen:    1,
		ifaces: []pkgapi.Interface{{Name: "stale"}},
	})
	m = nm.(rootModel)
	require.Equal(t, "keep", m.ifaces[0].Name)
	require.Equal(t, uint64(2), m.fetchGen)
}

func TestCurrentDataMsgApplied(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.fetchGen = 3
	nm, _ := m.Update(dataMsg{
		gen:    3,
		ifaces: []pkgapi.Interface{{Name: "fresh"}},
	})
	m = nm.(rootModel)
	require.Equal(t, "fresh", m.ifaces[0].Name)
	require.Equal(t, "ok", m.status)
}

func TestBusyIgnoresMutate(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.ifaces = []pkgapi.Interface{{Name: "wg0"}}
	m.tab = tabInterfaces
	m.cursor = 0
	m.busy = true
	nm, cmd := m.handleListKey("u")
	m = nm.(rootModel)
	require.True(t, m.busy)
	require.Nil(t, cmd)
}

func TestStartMutateSetsBusy(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	nm, cmd := m.startMutate(func() tea.Msg { return actionDoneMsg{flash: "ok", refresh: false} })
	m = nm.(rootModel)
	require.True(t, m.busy)
	require.NotNil(t, cmd)
	// second mutate ignored
	nm, cmd2 := m.startMutate(func() tea.Msg { return actionDoneMsg{} })
	m = nm.(rootModel)
	require.True(t, m.busy)
	require.Nil(t, cmd2)
}

func TestActionDoneClearsBusy(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.busy = true
	nm, _ := m.Update(actionDoneMsg{err: nil, flash: "done", refresh: false})
	m = nm.(rootModel)
	require.False(t, m.busy)
	require.Equal(t, "done", m.flash)
}

func TestActionDoneErrorClearsBusy(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.busy = true
	nm, _ := m.Update(actionDoneMsg{err: errString("boom")})
	m = nm.(rootModel)
	require.False(t, m.busy)
	require.Equal(t, "boom", m.err)
}

type errString string

func (e errString) Error() string { return string(e) }

func TestFlashClearOnlyMatchingID(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	m.flash = "hello"
	m.flashID = 5
	nm, _ := m.Update(flashClearMsg{id: 4})
	m = nm.(rootModel)
	require.Equal(t, "hello", m.flash)
	nm, _ = m.Update(flashClearMsg{id: 5})
	m = nm.(rootModel)
	require.Equal(t, "", m.flash)
}

func TestBeginFetchIncrementsGen(t *testing.T) {
	m := newRootModel(Config{Endpoint: "http://localhost"})
	require.Equal(t, uint64(0), m.fetchGen)
	m, cmd := m.beginFetch()
	require.Equal(t, uint64(1), m.fetchGen)
	require.NotNil(t, cmd)
	m, cmd = m.beginFetch()
	require.Equal(t, uint64(2), m.fetchGen)
	require.NotNil(t, cmd)
}
