package tui

import (
	"fmt"
	"strings"

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

	modeList        = 0
	modeIfaceForm   = 1
	modePeerForm    = 2
	modeIfaceDetail = 3
	modePeerDetail  = 4
	modeClientConf  = 5
	modeConfirm     = 6
)

type confirmKind int

const (
	confirmNone confirmKind = iota
	confirmDelIface
	confirmDelPeer
)

type rootModel struct {
	cfg    Config
	tab    int
	mode   int
	width  int
	height int

	ifaces []pkgapi.Interface
	peers  []pkgapi.Peer
	stats  *pkgapi.StatsSummary
	events []pkgapi.Event
	cursor int

	err    string
	status string
	flash  string

	lastKeys *pkgapi.KeyGenerateResponse

	form       formModel
	editName   string // iface name or peer key when editing
	editPub    string
	editIface  string
	formCreate bool

	confirm     confirmKind
	confirmText string
	confirmArg  string
	confirmArg2 string

	clientConf string
	detailPeer *pkgapi.Peer
	detailIf   *pkgapi.Interface
	scroll     int

	fetchGen uint64 // generation counter for in-flight data fetches
	busy     bool   // true while a mutating action is in flight
	flashID  int    // generation for flash clear; only matching id clears
}

func newRootModel(cfg Config) rootModel {
	return rootModel{cfg: cfg, status: "connecting…", mode: modeList}
}

// beginFetch bumps fetchGen and returns a fetch cmd tagged with that gen.
func (m rootModel) beginFetch() (rootModel, tea.Cmd) {
	m.fetchGen++
	return m, fetchData(m.cfg.Client, m.fetchGen)
}

// startMutate marks the model busy and returns cmd, or no-ops if already busy.
func (m rootModel) startMutate(cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if m.busy {
		return m, nil
	}
	m.busy = true
	return m, cmd
}

// setFlash stores a flash message and schedules a matching clear.
func (m rootModel) setFlash(s string) (rootModel, tea.Cmd) {
	m.flashID++
	m.flash = s
	return m, flashClearCmd(m.flashID)
}

func (m rootModel) Init() tea.Cmd {
	// fetchGen starts at 0; initial fetch uses gen 0 to match the model zero value
	// (Init cannot update the model).
	return tea.Batch(fetchData(m.cfg.Client, m.fetchGen), tickCmd(m.cfg.RefreshInterval))
}

func (m rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tickMsg:
		if m.mode == modeList {
			m, fetch := m.beginFetch()
			return m, tea.Batch(fetch, tickCmd(m.cfg.RefreshInterval))
		}
		return m, tickCmd(m.cfg.RefreshInterval)

	case flashClearMsg:
		if msg.id == m.flashID {
			m.flash = ""
		}
		return m, nil

	case dataMsg:
		if msg.gen != m.fetchGen {
			return m, nil // stale fetch
		}
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
			// refresh detail pointers
			if m.mode == modePeerDetail && m.detailPeer != nil {
				for i := range m.peers {
					if m.peers[i].PublicKey == m.detailPeer.PublicKey && m.peers[i].InterfaceName == m.detailPeer.InterfaceName {
						p := m.peers[i]
						m.detailPeer = &p
						break
					}
				}
			}
			if m.mode == modeIfaceDetail && m.detailIf != nil {
				for i := range m.ifaces {
					if m.ifaces[i].Name == m.detailIf.Name {
						iface := m.ifaces[i]
						m.detailIf = &iface
						break
					}
				}
			}
		}
		return m, nil

	case keysMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
		} else {
			m.lastKeys = msg.keys
			m.err = ""
			m, flashCmd := m.setFlash("keys generated")
			return m, flashCmd
		}
		return m, nil

	case actionDoneMsg:
		m.busy = false
		if msg.err != nil {
			m.err = msg.err.Error()
			m.status = "error"
			return m, nil
		}
		m.err = ""
		m.mode = modeList
		m.confirm = confirmNone
		m, flashCmd := m.setFlash(msg.flash)
		cmds := []tea.Cmd{flashCmd}
		if msg.refresh {
			var fetch tea.Cmd
			m, fetch = m.beginFetch()
			cmds = append(cmds, fetch)
		}
		return m, tea.Batch(cmds...)

	case clientConfMsg:
		if msg.err != nil {
			m.err = msg.err.Error()
			return m, nil
		}
		m.clientConf = msg.config
		m.mode = modeClientConf
		return m, nil

	case tea.KeyMsg:
		if m.mode == modeIfaceForm || m.mode == modePeerForm {
			return m.handleFormKeyAll(msg)
		}
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
	key := msg.String()

	// Global quit
	if key == "ctrl+c" {
		return m, tea.Quit
	}

	switch m.mode {
	case modeConfirm:
		return m.handleConfirm(key)
	case modeIfaceForm, modePeerForm:
		return m.handleFormKey(key)
	case modeIfaceDetail:
		return m.handleIfaceDetailKey(key)
	case modePeerDetail:
		return m.handlePeerDetailKey(key)
	case modeClientConf:
		if key == "esc" || key == "q" || key == "enter" {
			m.mode = modePeerDetail
			m.clientConf = ""
		}
		return m, nil
	default:
		return m.handleListKey(key)
	}
}

func (m rootModel) handleConfirm(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "y", "Y":
		if m.busy {
			return m, nil
		}
		switch m.confirm {
		case confirmDelIface:
			name := m.confirmArg
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeleteIface(m.cfg.Client, name))
		case confirmDelPeer:
			iface, pub := m.confirmArg, m.confirmArg2
			m.confirm = confirmNone
			m.mode = modeList
			return m.startMutate(doDeletePeer(m.cfg.Client, iface, pub))
		}
	case "n", "N", "esc":
		m.confirm = confirmNone
		m.mode = modeList
	}
	return m, nil
}

func (m rootModel) handleFormKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc":
		m.mode = modeList
		m.form.err = ""
		return m, nil
	case "enter":
		if m.mode == modeIfaceForm {
			return m.submitIfaceForm()
		}
		return m.submitPeerForm()
	}
	var cmd tea.Cmd
	m.form, cmd = m.form.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
	// re-dispatch properly — actually Update already got the KeyMsg from parent
	return m, cmd
}

// Fix: form keys should go through form.Update in Update() when mode is form.
// handleFormKey only for enter/esc; other keys via Update form path.
// But Update routes KeyMsg to handleKey first. So form needs all keys in handleFormKey.

func (m rootModel) handleFormKeyAll(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	key := msg.String()
	switch key {
	case "esc":
		m.mode = modeList
		return m, nil
	case "enter":
		if m.mode == modeIfaceForm {
			return m.submitIfaceForm()
		}
		return m.submitPeerForm()
	}
	var cmd tea.Cmd
	m.form, cmd = m.form.Update(msg)
	return m, cmd
}

func (m rootModel) submitIfaceForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if m.formCreate {
		name := v["name"]
		if name == "" {
			m.form.err = "name is required"
			return m, nil
		}
		port, err := parseIntField(v["port"])
		if err != nil {
			m.form.err = "invalid port"
			return m, nil
		}
		if port == 0 {
			port = 51820
		}
		mtu, _ := parseIntField(v["mtu"])
		fw, _ := parseIntField(v["fwmark"])
		tm, tid := parseTableFields(v["table"], v["table_id"])
		req := pkgapi.InterfaceCreateRequest{
			Name:           name,
			ListenPort:     port,
			Addresses:      splitCSV(v["addresses"]),
			DNS:            splitCSV(v["dns"]),
			MTU:            mtu,
			TableMode:      tm,
			TableID:        tid,
			FwMark:         fw,
			PublicEndpoint: v["public_endpoint"],
		}
		return m.startMutate(doCreateIface(m.cfg.Client, req))
	}
	// edit
	port, err := parseIntField(v["port"])
	if err != nil {
		m.form.err = "invalid port"
		return m, nil
	}
	mtu, _ := parseIntField(v["mtu"])
	fw, _ := parseIntField(v["fwmark"])
	tm, tid := parseTableFields(v["table"], v["table_id"])
	req := pkgapi.InterfaceUpdateRequest{
		ListenPort:     &port,
		Addresses:      splitCSV(v["addresses"]),
		DNS:            splitCSV(v["dns"]),
		TableMode:      &tm,
		TableID:        tid,
		FwMark:         &fw,
		PublicEndpoint: strPtr(v["public_endpoint"]),
	}
	if mtu > 0 {
		req.MTU = &mtu
	}
	return m.startMutate(doUpdateIface(m.cfg.Client, m.editName, req))
}

func parseTableFields(table, tableID string) (mode string, id *int) {
	mode = strings.ToLower(strings.TrimSpace(table))
	if mode == "" {
		mode = "auto"
	}
	if mode == "number" || mode == "custom" {
		mode = "number"
		if n, err := parseIntField(tableID); err == nil && n > 0 {
			id = &n
		}
		return mode, id
	}
	if n, err := parseIntField(mode); err == nil && n > 0 {
		mode = "number"
		id = &n
		return mode, id
	}
	if mode != "off" && mode != "auto" {
		mode = "auto"
	}
	return mode, nil
}

func (m rootModel) submitPeerForm() (tea.Model, tea.Cmd) {
	v := m.form.Values()
	if m.formCreate {
		iface := v["iface"]
		if iface == "" {
			m.form.err = "interface is required"
			return m, nil
		}
		ka, _ := parseIntField(v["keepalive"])
		tl, _ := parseInt64Field(v["traffic_limit"])
		rx, _ := parseInt64Field(v["bw_rx"])
		tx, _ := parseInt64Field(v["bw_tx"])
		req := pkgapi.PeerCreateRequest{
			PublicKey:           v["pubkey"],
			Name:                v["name"],
			AllowedIPs:          splitCSV(v["allowed_ips"]),
			AssignedIPs:         splitCSV(v["assigned_ips"]),
			Endpoint:            v["endpoint"],
			PersistentKeepalive: ka,
			GeneratePSK:         truthy(v["gen_psk"]),
			GenerateClientKey:   truthy(v["gen_client"]),
			TrafficLimitBytes:   tl,
			BandwidthRxBps:      rx,
			BandwidthTxBps:      tx,
		}
		if req.PublicKey == "" && !req.GenerateClientKey {
			m.form.err = "public key required (or gen client key = y)"
			return m, nil
		}
		return m.startMutate(doCreatePeer(m.cfg.Client, iface, req))
	}
	// edit
	ka, _ := parseIntField(v["keepalive"])
	tl, _ := parseInt64Field(v["traffic_limit"])
	rx, _ := parseInt64Field(v["bw_rx"])
	tx, _ := parseInt64Field(v["bw_tx"])
	req := pkgapi.PeerUpdateRequest{
		Name:                strPtr(v["name"]),
		AllowedIPs:          splitCSV(v["allowed_ips"]),
		AssignedIPs:         splitCSV(v["assigned_ips"]),
		Endpoint:            strPtr(v["endpoint"]),
		Notes:               strPtr(v["notes"]),
		PersistentKeepalive: &ka,
		TrafficLimitBytes:   &tl,
		BandwidthRxBps:      &rx,
		BandwidthTxBps:      &tx,
	}
	return m.startMutate(doUpdatePeer(m.cfg.Client, m.editIface, m.editPub, req))
}

func strPtr(s string) *string { return &s }

func (m rootModel) handleIfaceDetailKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "backspace":
		m.mode = modeList
		m.detailIf = nil
	case "u":
		if m.detailIf != nil {
			return m.startMutate(doIfaceUpDown(m.cfg.Client, m.detailIf.Name, true))
		}
	case "d":
		if m.detailIf != nil {
			return m.startMutate(doIfaceUpDown(m.cfg.Client, m.detailIf.Name, false))
		}
	case "e":
		if m.detailIf != nil {
			return m.openIfaceEdit(*m.detailIf)
		}
	case "x":
		if m.detailIf != nil {
			return m.startMutate(doExportIface(m.cfg.Client, m.detailIf.Name))
		}
	case "D":
		if m.detailIf != nil {
			m.confirm = confirmDelIface
			m.confirmText = fmt.Sprintf("Delete interface %s and all peers?", m.detailIf.Name)
			m.confirmArg = m.detailIf.Name
			m.mode = modeConfirm
		}
	case "n":
		if m.detailIf != nil {
			return m.openPeerCreate(m.detailIf.Name)
		}
	}
	return m, nil
}

func (m rootModel) handlePeerDetailKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "esc", "q", "backspace":
		m.mode = modeList
		m.detailPeer = nil
	case "s":
		if m.detailPeer != nil {
			return m.startMutate(doSuspend(m.cfg.Client, m.detailPeer.InterfaceName, m.detailPeer.PublicKey, !m.detailPeer.Suspended))
		}
	case "e":
		if m.detailPeer != nil {
			return m.openPeerEdit(*m.detailPeer)
		}
	case "t":
		if m.detailPeer != nil {
			return m.startMutate(doResetTraffic(m.cfg.Client, m.detailPeer.InterfaceName, m.detailPeer.PublicKey))
		}
	case "c":
		if m.detailPeer != nil {
			return m, doFetchClientConf(m.cfg.Client, m.detailPeer.InterfaceName, m.detailPeer.PublicKey)
		}
	case "D":
		if m.detailPeer != nil {
			m.confirm = confirmDelPeer
			m.confirmText = fmt.Sprintf("Delete peer %s on %s?", trunc(m.detailPeer.Name, 20), m.detailPeer.InterfaceName)
			m.confirmArg = m.detailPeer.InterfaceName
			m.confirmArg2 = m.detailPeer.PublicKey
			m.mode = modeConfirm
		}
	}
	return m, nil
}

func (m rootModel) handleListKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "q":
		return m, tea.Quit
	case "1":
		m.tab, m.cursor, m.scroll = tabInterfaces, 0, 0
	case "2":
		m.tab, m.cursor, m.scroll = tabPeers, 0, 0
	case "3":
		m.tab, m.cursor, m.scroll = tabStats, 0, 0
	case "4":
		m.tab, m.cursor, m.scroll = tabEvents, 0, 0
	case "5":
		m.tab, m.cursor, m.scroll = tabKeys, 0, 0
	case "tab", "right", "l":
		m.tab = (m.tab + 1) % 5
		m.cursor, m.scroll = 0, 0
	case "shift+tab", "left", "h":
		m.tab = (m.tab + 4) % 5
		m.cursor, m.scroll = 0, 0
	case "j", "down":
		if m.cursor < m.rowCount()-1 {
			m.cursor++
		}
	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
		}
	case "pgdown":
		m.cursor = min(m.rowCount()-1, m.cursor+10)
	case "pgup":
		m.cursor = max(0, m.cursor-10)
	case "r":
		m, fetch := m.beginFetch()
		return m, fetch
	case "R":
		return m.startMutate(doReconcile(m.cfg.Client))
	case "n":
		if m.tab == tabInterfaces {
			return m.openIfaceCreate()
		}
		if m.tab == tabPeers {
			iface := ""
			if len(m.ifaces) > 0 {
				iface = m.ifaces[0].Name
			}
			return m.openPeerCreate(iface)
		}
	case "enter", " ":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			iface := m.ifaces[m.cursor]
			m.detailIf = &iface
			m.mode = modeIfaceDetail
		}
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			p := m.peers[m.cursor]
			m.detailPeer = &p
			m.mode = modePeerDetail
		}
	case "u":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			return m.startMutate(doIfaceUpDown(m.cfg.Client, m.ifaces[m.cursor].Name, true))
		}
	case "d":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			return m.startMutate(doIfaceUpDown(m.cfg.Client, m.ifaces[m.cursor].Name, false))
		}
	case "e":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			return m.openIfaceEdit(m.ifaces[m.cursor])
		}
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			return m.openPeerEdit(m.peers[m.cursor])
		}
	case "D":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			name := m.ifaces[m.cursor].Name
			m.confirm = confirmDelIface
			m.confirmText = fmt.Sprintf("Delete interface %s?", name)
			m.confirmArg = name
			m.mode = modeConfirm
		}
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			p := m.peers[m.cursor]
			m.confirm = confirmDelPeer
			m.confirmText = fmt.Sprintf("Delete peer %s?", trunc(p.Name, 24))
			m.confirmArg = p.InterfaceName
			m.confirmArg2 = p.PublicKey
			m.mode = modeConfirm
		}
	case "s":
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			p := m.peers[m.cursor]
			return m.startMutate(doSuspend(m.cfg.Client, p.InterfaceName, p.PublicKey, !p.Suspended))
		}
	case "t":
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			p := m.peers[m.cursor]
			return m.startMutate(doResetTraffic(m.cfg.Client, p.InterfaceName, p.PublicKey))
		}
	case "c":
		if m.tab == tabPeers && m.cursor < len(m.peers) {
			p := m.peers[m.cursor]
			return m, doFetchClientConf(m.cfg.Client, p.InterfaceName, p.PublicKey)
		}
	case "x":
		if m.tab == tabInterfaces && m.cursor < len(m.ifaces) {
			return m.startMutate(doExportIface(m.cfg.Client, m.ifaces[m.cursor].Name))
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

func (m rootModel) openIfaceCreate() (tea.Model, tea.Cmd) {
	m.form = newForm("New interface", ifaceCreateFields(), map[string]string{
		"port": "51820", "table": "auto",
	})
	m.formCreate = true
	m.mode = modeIfaceForm
	return m, m.form.Init()
}

func (m rootModel) openIfaceEdit(iface pkgapi.Interface) (tea.Model, tea.Cmd) {
	tid := ""
	if iface.TableID != nil {
		tid = fmt.Sprintf("%d", *iface.TableID)
	}
	tm := iface.TableMode
	if tm == "" {
		tm = "auto"
	}
	m.form = newForm("Edit "+iface.Name, ifaceEditFields(), map[string]string{
		"port":            fmt.Sprintf("%d", iface.ListenPort),
		"addresses":       joinCSV(iface.Addresses),
		"dns":             joinCSV(iface.DNS),
		"mtu":             fmt.Sprintf("%d", iface.MTU),
		"table":           tm,
		"table_id":        tid,
		"fwmark":          fmt.Sprintf("%d", iface.FwMark),
		"public_endpoint": iface.PublicEndpoint,
	})
	m.formCreate = false
	m.editName = iface.Name
	m.mode = modeIfaceForm
	return m, m.form.Init()
}

func (m rootModel) openPeerCreate(iface string) (tea.Model, tea.Cmd) {
	m.form = newForm("New peer", peerCreateFields(), map[string]string{
		"iface": iface, "gen_psk": "y", "gen_client": "y", "keepalive": "25",
	})
	m.formCreate = true
	m.mode = modePeerForm
	return m, m.form.Init()
}

func (m rootModel) openPeerEdit(p pkgapi.Peer) (tea.Model, tea.Cmd) {
	m.form = newForm("Edit peer "+trunc(p.Name, 20), peerEditFields(), map[string]string{
		"name":          p.Name,
		"allowed_ips":   joinCSV(p.AllowedIPs),
		"assigned_ips":  joinCSV(p.AssignedIPs),
		"endpoint":      p.Endpoint,
		"keepalive":     fmt.Sprintf("%d", p.PersistentKeepalive),
		"notes":         p.Notes,
		"traffic_limit": fmt.Sprintf("%d", p.TrafficLimitBytes),
		"bw_rx":         fmt.Sprintf("%d", p.BandwidthRxBps),
		"bw_tx":         fmt.Sprintf("%d", p.BandwidthTxBps),
	})
	m.formCreate = false
	m.editIface = p.InterfaceName
	m.editPub = p.PublicKey
	m.mode = modePeerForm
	return m, m.form.Init()
}

// ---- View ----

func (m rootModel) View() string {
	var b strings.Builder
	b.WriteString(statusStyle.Render(fmt.Sprintf(" wireguardctl · %s · %s ", m.cfg.Endpoint, m.status)))
	if m.flash != "" {
		b.WriteString(" ")
		b.WriteString(okStyle.Render("✓ " + m.flash))
	}
	b.WriteString("\n")

	if m.mode == modeList {
		b.WriteString(m.renderTabs())
		b.WriteString("\n\n")
	}

	if m.err != "" && m.mode != modeIfaceForm && m.mode != modePeerForm {
		b.WriteString(errStyle.Render("error: " + m.err))
		b.WriteString("\n\n")
	}

	switch m.mode {
	case modeConfirm:
		b.WriteString(panelStyle.Render(
			warnStyle.Render("Confirm") + "\n\n" + m.confirmText + "\n\n" +
				helpStyle.Render("[y] yes  [n/esc] cancel"),
		))
	case modeIfaceForm, modePeerForm:
		b.WriteString(m.form.View())
	case modeIfaceDetail:
		b.WriteString(m.viewIfaceDetail())
	case modePeerDetail:
		b.WriteString(m.viewPeerDetail())
	case modeClientConf:
		b.WriteString(m.viewClientConf())
	default:
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
		b.WriteString(helpStyle.Render(m.listHelp()))
	}
	return b.String()
}

func (m rootModel) listHelp() string {
	base := "1-5 tabs · j/k · enter detail · n new · e edit · r refresh · R reconcile · q quit"
	switch m.tab {
	case tabInterfaces:
		return base + " · u/d up/down · D delete · x export"
	case tabPeers:
		return base + " · s suspend · t reset traffic · c client-conf · D delete"
	case tabKeys:
		return base + " · g keypair · p psk"
	default:
		return base
	}
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
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-10s %-6s %6s %6s %10s %10s %10s %s",
		"NAME", "STATE", "PORT", "PEERS", "RX/s", "TX/s", "RX", "ENDPOINT")))
	b.WriteString("\n")
	for i, iface := range m.ifaces {
		state := badgeDown.Render("DOWN")
		if iface.Up {
			state = badgeUp.Render(" UP ")
		}
		line := fmt.Sprintf("%-10s %s %6d %6d %10s %10s %10s %s",
			iface.Name, state, iface.ListenPort, iface.PeerCount,
			formatBps(iface.RxBps), formatBps(iface.TxBps), formatBytes(iface.RxBytes),
			trunc(iface.PublicEndpoint, 24))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.ifaces) == 0 {
		b.WriteString(helpStyle.Render("(no interfaces — press n to create)"))
	}
	return b.String()
}

func (m rootModel) viewPeers() string {
	var b strings.Builder
	b.WriteString(headerStyle.Render(fmt.Sprintf("%-8s %-12s %-12s %-6s %10s %10s %s",
		"IFACE", "NAME", "PUBKEY", "STATE", "RX/s", "TOTAL", "ENDPOINT")))
	b.WriteString("\n")
	for i, p := range m.peers {
		var state string
		switch {
		case p.Suspended:
			state = badgeSusp.Render("SUSP")
		case p.Connected:
			state = badgeConn.Render("CONN")
		default:
			state = dimStyle.Render("idle")
		}
		line := fmt.Sprintf("%-8s %-12s %-12s %s %10s %10s %s",
			p.InterfaceName, trunc(p.Name, 12), wgutil.ShortKey(p.PublicKey), state,
			formatBps(p.RxBps), formatBytes(p.RxBytes+p.TxBytes), trunc(firstNonEmpty(p.LastEndpoint, p.Endpoint), 22))
		if i == m.cursor {
			line = selStyle.Render(line)
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	if len(m.peers) == 0 {
		b.WriteString(helpStyle.Render("(no peers — press n to create)"))
	}
	return b.String()
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func (m rootModel) viewStats() string {
	if m.stats == nil {
		return helpStyle.Render("no stats yet")
	}
	s := m.stats
	body := fmt.Sprintf(
		"  Interfaces   %d\n  Peers        %d\n  Connected    %d\n  Suspended    %d\n\n  RX total     %s  (%s)\n  TX total     %s  (%s)\n",
		s.Interfaces, s.Peers, s.Connected, s.Suspended,
		formatBytes(s.RxBytes), formatBps(s.RxBps),
		formatBytes(s.TxBytes), formatBps(s.TxBps),
	)
	return panelStyle.Render(titleStyle.Render("Global stats") + "\n" + body)
}

func (m rootModel) viewEvents() string {
	var b strings.Builder
	limit := 40
	if m.height > 10 {
		limit = m.height - 8
	}
	for i, e := range m.events {
		if i >= limit {
			break
		}
		line := fmt.Sprintf("%s %-5s %-7s %-8s %s",
			e.TS.Format("15:04:05"), e.Level, e.Kind, trunc(e.Interface, 8), e.Message)
		if i == m.cursor {
			line = selStyle.Render(line)
		} else if e.Level == "warn" || e.Level == "error" {
			line = warnStyle.Render(line)
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
	b.WriteString(titleStyle.Render("Key generator"))
	b.WriteString("\n")
	b.WriteString("  g  generate WireGuard keypair\n")
	b.WriteString("  p  generate preshared key\n\n")
	if m.lastKeys != nil {
		inner := ""
		if m.lastKeys.PrivateKey != "" {
			inner += "PrivateKey   " + m.lastKeys.PrivateKey + "\n"
			inner += "PublicKey    " + m.lastKeys.PublicKey + "\n"
		}
		if m.lastKeys.PresharedKey != "" {
			inner += "PresharedKey " + m.lastKeys.PresharedKey + "\n"
		}
		b.WriteString(panelStyle.Render(inner))
	} else {
		b.WriteString(dimStyle.Render("  (no keys generated this session)"))
	}
	return b.String()
}

func (m rootModel) viewIfaceDetail() string {
	if m.detailIf == nil {
		return ""
	}
	i := m.detailIf
	state := "DOWN"
	if i.Up {
		state = "UP"
	}
	body := strings.Builder{}
	kv := func(k, v string) {
		body.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render(k), valueStyle.Render(v)))
	}
	kv("Name", i.Name)
	kv("State", state)
	kv("Public key", i.PublicKey)
	kv("Listen port", fmt.Sprintf("%d", i.ListenPort))
	kv("Addresses", joinCSV(i.Addresses))
	kv("DNS", joinCSV(i.DNS))
	kv("MTU", fmt.Sprintf("%d", i.MTU))
	table := i.TableMode
	if table == "number" && i.TableID != nil {
		table = fmt.Sprintf("%d", *i.TableID)
	}
	if table == "" {
		table = "auto"
	}
	kv("Table", table)
	kv("FwMark", fmt.Sprintf("%d", i.FwMark))
	kv("Public endpoint", i.PublicEndpoint)
	kv("Peers", fmt.Sprintf("%d", i.PeerCount))
	kv("RX / TX", formatBytes(i.RxBytes)+" / "+formatBytes(i.TxBytes))
	kv("RX/s TX/s", formatBps(i.RxBps)+" / "+formatBps(i.TxBps))
	help := helpStyle.Render("esc back · e edit · u/d up/down · n add peer · x export · D delete")
	return panelStyle.Render(titleStyle.Render("Interface "+i.Name) + "\n" + body.String() + "\n" + help)
}

func (m rootModel) viewPeerDetail() string {
	if m.detailPeer == nil {
		return ""
	}
	p := m.detailPeer
	state := "idle"
	if p.Suspended {
		state = "SUSPENDED"
	} else if p.Connected {
		state = "connected"
	}
	body := strings.Builder{}
	kv := func(k, v string) {
		body.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render(k), valueStyle.Render(v)))
	}
	kv("Name", p.Name)
	kv("Interface", p.InterfaceName)
	kv("Public key", p.PublicKey)
	kv("State", state)
	kv("Endpoint", firstNonEmpty(p.LastEndpoint, p.Endpoint))
	kv("AllowedIPs", joinCSV(p.AllowedIPs))
	kv("Assigned IPs", joinCSV(p.AssignedIPs))
	kv("Keepalive", fmt.Sprintf("%d", p.PersistentKeepalive))
	kv("RX / TX", formatBytes(p.RxBytes)+" / "+formatBytes(p.TxBytes))
	kv("RX/s TX/s", formatBps(p.RxBps)+" / "+formatBps(p.TxBps))
	kv("Traffic limit", fmt.Sprintf("%d B", p.TrafficLimitBytes))
	kv("BW limits", fmt.Sprintf("rx=%d tx=%d bps", p.BandwidthRxBps, p.BandwidthTxBps))
	kv("Last handshake", p.LastHandshakeAt)
	kv("Notes", p.Notes)
	help := helpStyle.Render("esc back · e edit · s suspend/resume · t reset traffic · c client conf · D delete")
	return panelStyle.Render(titleStyle.Render("Peer "+firstNonEmpty(p.Name, wgutil.ShortKey(p.PublicKey))) + "\n" + body.String() + "\n" + help)
}

func (m rootModel) viewClientConf() string {
	help := helpStyle.Render("esc/enter back  ·  copy config from terminal")
	return panelStyle.Render(titleStyle.Render("Client config") + "\n\n" + m.clientConf + "\n" + help)
}
