package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

// fieldDef describes a form field.
type fieldDef struct {
	Key   string
	Label string
	Hint  string
	Width int
}

type formModel struct {
	title  string
	fields []fieldDef
	inputs []textinput.Model
	focus  int
	err    string
}

func newForm(title string, fields []fieldDef, values map[string]string) formModel {
	inputs := make([]textinput.Model, len(fields))
	for i, f := range fields {
		ti := textinput.New()
		ti.Placeholder = f.Hint
		w := f.Width
		if w <= 0 {
			w = 48
		}
		ti.CharLimit = 256
		ti.Width = w
		if values != nil {
			if v, ok := values[f.Key]; ok {
				ti.SetValue(v)
			}
		}
		if i == 0 {
			ti.Focus()
		}
		inputs[i] = ti
	}
	return formModel{title: title, fields: fields, inputs: inputs, focus: 0}
}

func (f formModel) Init() tea.Cmd { return textinput.Blink }

func (f formModel) Update(msg tea.Msg) (formModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			f.focus = (f.focus + 1) % len(f.inputs)
			return f, f.focusInput()
		case "shift+tab", "up":
			f.focus = (f.focus + len(f.inputs) - 1) % len(f.inputs)
			return f, f.focusInput()
		}
	}
	var cmd tea.Cmd
	f.inputs[f.focus], cmd = f.inputs[f.focus].Update(msg)
	return f, cmd
}

func (f *formModel) focusInput() tea.Cmd {
	for i := range f.inputs {
		if i == f.focus {
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
		out[field.Key] = strings.TrimSpace(f.inputs[i].Value())
	}
	return out
}

func (f formModel) Get(key string) string {
	for i, field := range f.fields {
		if field.Key == key {
			return strings.TrimSpace(f.inputs[i].Value())
		}
	}
	return ""
}

func (f formModel) View() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render(f.title))
	b.WriteString("\n")
	if f.err != "" {
		b.WriteString(errStyle.Render(f.err))
		b.WriteString("\n\n")
	}
	for i, field := range f.fields {
		label := field.Label
		if i == f.focus {
			label = focusStyle.Render("› " + label)
		} else {
			label = labelStyle.Render("  " + label)
		}
		b.WriteString(fmt.Sprintf("%s %s\n", label, f.inputs[i].View()))
	}
	b.WriteString("\n")
	b.WriteString(helpStyle.Render("tab/↑↓ fields · enter submit · esc cancel"))
	return panelStyle.Render(b.String())
}

// Standard form field sets.
func ifaceCreateFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "wg0"},
		{Key: "port", Label: "Listen port", Hint: "51820"},
		{Key: "addresses", Label: "Addresses", Hint: "10.7.0.1/24, fd00::1/64"},
		{Key: "dns", Label: "DNS", Hint: "1.1.1.1, 2606:4700:4700::1111"},
		{Key: "mtu", Label: "MTU", Hint: "1420 (optional)"},
		{Key: "public_endpoint", Label: "Public endpoint", Hint: "vpn.example.com:51820"},
	}
}

func ifaceEditFields() []fieldDef {
	return []fieldDef{
		{Key: "port", Label: "Listen port", Hint: "51820"},
		{Key: "addresses", Label: "Addresses", Hint: "10.7.0.1/24, fd00::1/64"},
		{Key: "dns", Label: "DNS", Hint: "1.1.1.1"},
		{Key: "mtu", Label: "MTU", Hint: "1420"},
		{Key: "public_endpoint", Label: "Public endpoint", Hint: "vpn.example.com:51820"},
	}
}

func peerCreateFields() []fieldDef {
	return []fieldDef{
		{Key: "iface", Label: "Interface", Hint: "wg0"},
		{Key: "name", Label: "Name", Hint: "alice"},
		{Key: "pubkey", Label: "Public key", Hint: "empty + gen client key"},
		{Key: "allowed_ips", Label: "AllowedIPs", Hint: "10.7.0.2/32, fd00::2/128"},
		{Key: "assigned_ips", Label: "Assigned IPs", Hint: "10.7.0.2, fd00::2"},
		{Key: "endpoint", Label: "Endpoint", Hint: "optional host:port"},
		{Key: "keepalive", Label: "Keepalive", Hint: "25"},
		{Key: "gen_psk", Label: "Generate PSK", Hint: "y/n"},
		{Key: "gen_client", Label: "Gen client key", Hint: "y/n (for conf/QR)"},
		{Key: "traffic_limit", Label: "Traffic limit B", Hint: "0=unlimited"},
		{Key: "bw_rx", Label: "BW RX bps", Hint: "0=unlimited"},
		{Key: "bw_tx", Label: "BW TX bps", Hint: "0=unlimited"},
	}
}

func peerEditFields() []fieldDef {
	return []fieldDef{
		{Key: "name", Label: "Name", Hint: "alice"},
		{Key: "allowed_ips", Label: "AllowedIPs", Hint: "10.7.0.2/32"},
		{Key: "assigned_ips", Label: "Assigned IPs", Hint: "10.7.0.2"},
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
