package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	tabActive  = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("15")).Background(lipgloss.Color("62")).Padding(0, 1)
	tabInactive = lipgloss.NewStyle().Foreground(lipgloss.Color("246")).Padding(0, 1)
	helpStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	errStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	okStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("42"))
	headerStyle = lipgloss.NewStyle().Bold(true).Underline(true)
	statusStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("229")).Background(lipgloss.Color("57")).Padding(0, 1)
)
