package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
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
	help   string
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
		if kind == fieldText && i == firstTextIndex(fields) {
			ti.Focus()
		}
		inputs[i] = ti
	}
	// focus first field
	f := formModel{title: title, fields: fields, inputs: inputs, selIdx: selIdx, focus: 0}
	_ = f.focusInput()
	return f
}

func firstTextIndex(fields []fieldDef) int {
	for i, f := range fields {
		if f.Kind == "" || f.Kind == fieldText {
			return i
		}
	}
	return 0
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
	// text input only when focused field is text
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

func (f *formModel) SetWidth(w int) {
	f.width = w
	iw := w - 28
	if iw < 20 {
		iw = 20
	}
	if iw > 80 {
		iw = 80
	}
	for i := range f.inputs {
		f.inputs[i].Width = iw
	}
}

func (f formModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(f.title))
	b.WriteString("\n")
	if f.err != "" {
		b.WriteString(errStyle.Render("✗ " + f.err))
		b.WriteString("\n\n")
	}
	for i, field := range f.fields {
		label := field.Label
		if i == f.focus {
			label = focusStyle.Render(" › " + label + " ")
		} else {
			label = labelStyle.Render("   " + label)
		}
		var val string
		switch field.Kind {
		case fieldSelect:
			opts := field.Options
			if len(opts) == 0 {
				val = dimStyle.Render("(none)")
			} else {
				idx := f.selIdx[i]
				if idx < 0 || idx >= len(opts) {
					idx = 0
				}
				// show current with neighbors
				cur := opts[idx]
				if i == f.focus {
					val = selStyle.Render("◀ "+cur+" ▶") + dimStyle.Render(fmt.Sprintf("  %d/%d  ←/→", idx+1, len(opts)))
				} else {
					val = valueStyle.Render(cur)
				}
			}
		case fieldBool:
			on := f.selIdx[i] == 1
			if i == f.focus {
				if on {
					val = okStyle.Render("[✓ yes]") + dimStyle.Render("  ←/→ or space")
				} else {
					val = dimStyle.Render("[  no ]") + dimStyle.Render("  ←/→ or space")
				}
			} else if on {
				val = okStyle.Render("yes")
			} else {
				val = dimStyle.Render("no")
			}
		default:
			val = f.inputs[i].View()
		}
		b.WriteString(fmt.Sprintf("%s %s\n", label, val))
		if field.Hint != "" && i == f.focus {
			b.WriteString(dimStyle.Render("       " + field.Hint))
			b.WriteString("\n")
		}
	}
	b.WriteString("\n")
	help := f.help
	if help == "" {
		help = "tab/↑↓ fields · ←/→ or space select · enter submit · esc cancel"
	}
	b.WriteString(helpStyle.Render(help))
	body := b.String()
	if f.width > 10 {
		return panelStyle.Width(f.width - 4).Render(body)
	}
	return panelStyle.Render(body)
}

// Standard form field sets.
func ifaceCreateFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "wg0"},
		{Key: "port", Label: "Listen port", Hint: "51820"},
		{Key: "addresses", Label: "Addresses", Hint: "CIDR list: 10.7.0.1/24, fd00::1/64"},
		{Key: "dns", Label: "DNS", Hint: "1.1.1.1 or domains (optional)"},
		{Key: "mtu", Label: "MTU", Hint: "1420 (optional)"},
		{Key: "table", Label: "Table", Hint: "auto | off | number"},
		{Key: "table_id", Label: "Table ID", Hint: "when table=number"},
		{Key: "fwmark", Label: "FwMark", Hint: "0=auto from port"},
		{Key: "public_endpoint", Label: "Public endpoint", Hint: "vpn.example.com:51820"},
	}
}

func ifaceEditFields() []fieldDef {
	return []fieldDef{
		{Key: "port", Label: "Listen port", Hint: "51820"},
		{Key: "addresses", Label: "Addresses", Hint: "CIDR list only"},
		{Key: "dns", Label: "DNS", Hint: "optional"},
		{Key: "mtu", Label: "MTU", Hint: "1420"},
		{Key: "table", Label: "Table", Hint: "auto | off | number"},
		{Key: "table_id", Label: "Table ID", Hint: "when table=number"},
		{Key: "fwmark", Label: "FwMark", Hint: "0=auto"},
		{Key: "public_endpoint", Label: "Public endpoint", Hint: "host:port"},
	}
}

func peerCreateFields(ifaces []string) []fieldDef {
	opts := append([]string{}, ifaces...)
	if len(opts) == 0 {
		opts = []string{""}
	}
	return []fieldDef{
		{Key: "iface", Label: "Interface", Hint: "←/→ select interface", Kind: fieldSelect, Options: opts},
		{Key: "name", Label: "Name", Hint: "alice"},
		{Key: "pubkey", Label: "Public key", Hint: "leave empty if gen client key = yes"},
		{Key: "auto_ip", Label: "Auto IP", Hint: "allocate next free IP from interface subnet", Kind: fieldBool},
		{Key: "allowed_ips", Label: "AllowedIPs", Hint: "auto or 10.7.0.2/32 — must be valid CIDR"},
		{Key: "assigned_ips", Label: "Assigned IPs", Hint: "auto or 10.7.0.2 — client tunnel address"},
		{Key: "endpoint", Label: "Endpoint", Hint: "optional host:port"},
		{Key: "keepalive", Label: "Keepalive", Hint: "25"},
		{Key: "gen_psk", Label: "Generate PSK", Kind: fieldBool},
		{Key: "gen_client", Label: "Gen client key", Hint: "for conf/QR export", Kind: fieldBool},
		{Key: "traffic_limit", Label: "Traffic limit B", Hint: "0=unlimited"},
		{Key: "bw_rx", Label: "BW RX bps", Hint: "0=unlimited"},
		{Key: "bw_tx", Label: "BW TX bps", Hint: "0=unlimited"},
	}
}

func peerEditFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "alice"},
		{Key: "auto_ip", Label: "Re-auto IP", Hint: "yes = allocate next free from interface", Kind: fieldBool},
		{Key: "allowed_ips", Label: "AllowedIPs", Hint: "valid CIDRs"},
		{Key: "assigned_ips", Label: "Assigned IPs", Hint: "client addresses"},
		{Key: "endpoint", Label: "Endpoint", Hint: "host:port"},
		{Key: "keepalive", Label: "Keepalive", Hint: "25"},
		{Key: "notes", Label: "Notes", Hint: "optional"},
		{Key: "traffic_limit", Label: "Traffic limit B", Hint: "0=unlimited"},
		{Key: "bw_rx", Label: "BW RX bps", Hint: "0=unlimited"},
		{Key: "bw_tx", Label: "BW TX bps", Hint: "0=unlimited"},
	}
}

func truthy(s string) bool {
	s = strings.ToLower(strings.TrimSpace(s))
	return s == "y" || s == "yes" || s == "true" || s == "1"
}
