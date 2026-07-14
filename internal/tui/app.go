package tui

import (
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
