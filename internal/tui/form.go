package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// field kinds
const (
	fieldText   = "text"
	fieldSelect = "select"
	fieldBool   = "bool"
)

// fieldDef describes a form field.
type fieldDef struct {
	Key     string
	Label   string
	Hint    string
	Width   int
	Kind    string   // text | select | bool
	Options []string // select options
}

type formModel struct {
	title  string
	fields []fieldDef
	inputs []textinput.Model
	selIdx []int // for select/bool fields
	focus  int
	err    string
	width  int
	height int
	help   string
	// footer note (e.g. IP pool status)
	note string
}

func newForm(title string, fields []fieldDef, values map[string]string) formModel {
	inputs := make([]textinput.Model, len(fields))
	selIdx := make([]int, len(fields))
	for i, f := range fields {
		kind := f.Kind
		if kind == "" {
			kind = fieldText
		}
		fields[i].Kind = kind
		ti := textinput.New()
		ti.Placeholder = f.Hint
		w := f.Width
		if w <= 0 {
			w = 56
		}
		ti.CharLimit = 512
		ti.Width = w
		ti.Prompt = ""
		if values != nil {
			if v, ok := values[f.Key]; ok {
				switch kind {
				case fieldSelect:
					selIdx[i] = indexOf(f.Options, v)
					if selIdx[i] < 0 && len(f.Options) > 0 {
						selIdx[i] = 0
					}
				case fieldBool:
					if truthy(v) {
						selIdx[i] = 1
					}
				default:
					ti.SetValue(v)
				}
			}
		}
		inputs[i] = ti
	}
	f := formModel{title: title, fields: fields, inputs: inputs, selIdx: selIdx, focus: 0}
	_ = f.focusInput()
	return f
}

func indexOf(opts []string, v string) int {
	v = strings.TrimSpace(v)
	for i, o := range opts {
		if o == v {
			return i
		}
	}
	return -1
}

func (f formModel) Init() tea.Cmd { return textinput.Blink }

func (f formModel) Update(msg tea.Msg) (formModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			f.focus = (f.focus + 1) % len(f.fields)
			return f, f.focusInput()
		case "shift+tab", "up":
			f.focus = (f.focus + len(f.fields) - 1) % len(f.fields)
			return f, f.focusInput()
		case "left", "h":
			if f.fields[f.focus].Kind == fieldSelect || f.fields[f.focus].Kind == fieldBool {
				f.cycleSelect(f.focus, -1)
				return f, nil
			}
		case "right", "l", " ":
			if f.fields[f.focus].Kind == fieldSelect || f.fields[f.focus].Kind == fieldBool {
				f.cycleSelect(f.focus, +1)
				return f, nil
			}
		}
	}
	if f.fields[f.focus].Kind == fieldText {
		var cmd tea.Cmd
		f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
		return f, cmd
	}
	return f, nil
}

func (f *formModel) cycleSelect(i, delta int) {
	opts := f.fields[i].Options
	if f.fields[i].Kind == fieldBool {
		opts = []string{"n", "y"}
	}
	if len(opts) == 0 {
		return
	}
	f.selIdx[i] = (f.selIdx[i] + delta + len(opts)) % len(opts)
}

func (f *formModel) focusInput() tea.Cmd {
	for i := range f.inputs {
		if i == f.focus && f.fields[i].Kind == fieldText {
			f.inputs[i].Focus()
		} else {
			f.inputs[i].Blur()
		}
	}
	return textinput.Blink
}

// SetFieldValue sets a text field by key (e.g. after re-auto IP).
func (f *formModel) SetFieldValue(key, val string) {
	for i, field := range f.fields {
		if field.Key == key && field.Kind == fieldText {
			f.inputs[i].SetValue(val)
			return
		}
	}
}

// SetSelectOptions updates select options and tries to keep current selection.
func (f *formModel) SetSelectOptions(key string, opts []string) {
	for i, field := range f.fields {
		if field.Key != key {
			continue
		}
		cur := ""
		if len(field.Options) > 0 && f.selIdx[i] >= 0 && f.selIdx[i] < len(field.Options) {
			cur = field.Options[f.selIdx[i]]
		}
		f.fields[i].Options = opts
		f.selIdx[i] = indexOf(opts, cur)
		if f.selIdx[i] < 0 {
			f.selIdx[i] = 0
		}
		return
	}
}

func (f formModel) Values() map[string]string {
	out := make(map[string]string, len(f.fields))
	for i, field := range f.fields {
		switch field.Kind {
		case fieldSelect:
			if len(field.Options) > 0 {
				idx := f.selIdx[i]
				if idx < 0 || idx >= len(field.Options) {
					idx = 0
				}
				out[field.Key] = field.Options[idx]
			}
		case fieldBool:
			if f.selIdx[i] == 1 {
				out[field.Key] = "y"
			} else {
				out[field.Key] = "n"
			}
		default:
			out[field.Key] = strings.TrimSpace(f.inputs[i].Value())
		}
	}
	return out
}

func (f formModel) Get(key string) string {
	return f.Values()[key]
}

func (f formModel) FocusedKey() string {
	if f.focus >= 0 && f.focus < len(f.fields) {
		return f.fields[f.focus].Key
	}
	return ""
}

func (f *formModel) SetSize(w, h int) {
	f.width = w
	f.height = h
	iw := w - 26
	if iw < 24 {
		iw = 24
	}
	if iw > 100 {
		iw = 100
	}
	for i := range f.inputs {
		f.inputs[i].Width = iw
	}
}

func (f formModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(f.title))
	b.WriteString("\n\n")
	if f.err != "" {
		b.WriteString(errStyle.Render("✗  " + f.err))
		b.WriteString("\n\n")
	}
	if f.note != "" {
		b.WriteString(okStyle.Render("  " + f.note))
		b.WriteString("\n\n")
	}
	for i, field := range f.fields {
		focused := i == f.focus
		var label string
		if focused {
			label = focusStyle.Render(fmt.Sprintf(" %-16s ", field.Label))
		} else {
			label = labelStyle.Width(18).Render(" " + field.Label)
		}
		var val string
		switch field.Kind {
		case fieldSelect:
			opts := field.Options
			if len(opts) == 0 {
				val = dimStyle.Render("(none available)")
			} else {
				idx := f.selIdx[i]
				if idx < 0 || idx >= len(opts) {
					idx = 0
				}
				cur := opts[idx]
				if focused {
					val = selStyle.Render(" ◀ "+cur+" ▶ ") + dimStyle.Render(fmt.Sprintf(" %d/%d", idx+1, len(opts)))
				} else {
					val = valueStyle.Render(cur)
				}
			}
		case fieldBool:
			on := f.selIdx[i] == 1
			if focused {
				if on {
					val = okStyle.Render(" [ ON  ] ") + dimStyle.Render("space/←→ toggle")
				} else {
					val = dimStyle.Render(" [ off ] ") + dimStyle.Render("space/←→ toggle")
				}
			} else if on {
				val = okStyle.Render("on")
			} else {
				val = dimStyle.Render("off")
			}
		default:
			val = f.inputs[i].View()
		}
		b.WriteString(label)
		b.WriteString("  ")
		b.WriteString(val)
		b.WriteString("\n")
		if field.Hint != "" && focused {
			b.WriteString(dimStyle.Render("                    " + field.Hint))
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	help := f.help
	if help == "" {
		help = "tab/↑↓ move  ·  ←/→ or space change  ·  enter save  ·  esc cancel"
	}
	b.WriteString(helpStyle.Render(help))

	inner := b.String()
	w := f.width
	if w < 40 {
		w = 80
	}
	// Fill remaining form area with a full-size panel.
	box := panelStyle.Width(w - 2)
	if f.height > 6 {
		// content height inside border/padding
		box = box.Height(f.height - 2)
	}
	return box.Render(inner)
}

// --- Field sets ---

func ifaceCreateFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "e.g. wg0"},
		{Key: "port", Label: "Listen port", Hint: "51820"},
		{Key: "addresses", Label: "Server addr", Hint: "CIDR required — e.g. 10.7.0.1/24"},
		{Key: "dns", Label: "DNS", Hint: "optional — 1.1.1.1"},
		{Key: "mtu", Label: "MTU", Hint: "optional — 1420"},
		{Key: "table", Label: "Table", Hint: "auto | off | number"},
		{Key: "table_id", Label: "Table ID", Hint: "only if table=number"},
		{Key: "fwmark", Label: "FwMark", Hint: "0 = auto"},
		{Key: "public_endpoint", Label: "Public endpt", Hint: "vpn.example.com:51820"},
	}
}

func ifaceEditFields() []fieldDef {
	return []fieldDef{
		{Key: "port", Label: "Listen port", Hint: "51820"},
		{Key: "addresses", Label: "Server addr", Hint: "CIDR list"},
		{Key: "dns", Label: "DNS", Hint: "optional"},
		{Key: "mtu", Label: "MTU", Hint: "1420"},
		{Key: "table", Label: "Table", Hint: "auto | off | number"},
		{Key: "table_id", Label: "Table ID", Hint: "if number"},
		{Key: "fwmark", Label: "FwMark", Hint: "0=auto"},
		{Key: "public_endpoint", Label: "Public endpt", Hint: "host:port"},
	}
}

// peerCreateFields — simple path: pick iface, name, tunnel IP (pre-filled free).
func peerCreateFields(ifaces []string) []fieldDef {
	opts := append([]string{}, ifaces...)
	if len(opts) == 0 {
		opts = []string{"(no interfaces)"}
	}
	return []fieldDef{
		{Key: "iface", Label: "Interface", Hint: "←/→ choose which WireGuard iface", Kind: fieldSelect, Options: opts},
		{Key: "name", Label: "Name", Hint: "friendly name — alice, phone, …"},
		{Key: "tunnel_ip", Label: "Tunnel IP", Hint: "next free IP is filled in — edit or press a to re-pick"},
		{Key: "gen_client", Label: "Client key", Hint: "generate keypair so conf/QR works", Kind: fieldBool},
		{Key: "gen_psk", Label: "PSK", Hint: "shared secret", Kind: fieldBool},
		{Key: "keepalive", Label: "Keepalive", Hint: "seconds — 25 is typical"},
		{Key: "pubkey", Label: "Public key", Hint: "only if client key = off (paste peer pubkey)"},
		{Key: "endpoint", Label: "Endpoint", Hint: "optional peer host:port"},
		{Key: "traffic_limit", Label: "Quota (B)", Hint: "0 = unlimited"},
		{Key: "bw_rx", Label: "BW RX bps", Hint: "0 = unlimited"},
		{Key: "bw_tx", Label: "BW TX bps", Hint: "0 = unlimited"},
	}
}

func peerEditFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "friendly name"},
		{Key: "tunnel_ip", Label: "Tunnel IP", Hint: "press a for next free IP, or edit"},
		{Key: "endpoint", Label: "Endpoint", Hint: "host:port"},
		{Key: "keepalive", Label: "Keepalive", Hint: "seconds"},
		{Key: "notes", Label: "Notes", Hint: "optional"},
		{Key: "traffic_limit", Label: "Quota (B)", Hint: "0 = unlimited"},
		{Key: "bw_rx", Label: "BW RX bps", Hint: "0 = unlimited"},
		{Key: "bw_tx", Label: "BW TX bps", Hint: "0 = unlimited"},
	}
}

func truthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes" || s == "true" || s == "1" || s == "on"
}

// layout helpers used by root view
func fillHeight(content string, width, height int) string {
	if height < 1 {
		height = 1
	}
	if width < 1 {
		width = 1
	}
	style := lipgloss.NewStyle().Width(width).Height(height).MaxHeight(height)
	return style.Render(content)
}
