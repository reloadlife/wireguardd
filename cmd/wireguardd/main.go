package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/reloadlife/wireguardd/internal/config"
	"github.com/reloadlife/wireguardd/internal/daemon"
	"github.com/reloadlife/wireguardd/internal/version"
)

func main() {
	root := &cobra.Command{
		Use:   "wireguardd",
		Short: "WireGuard management daemon",
	}
	root.AddCommand(versionCmd(), runCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println(version.String())
		},
	}
}

func runCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadDaemon(configPath)
			if err != nil {
				return err
			}
			log := newLogger(cfg.Log.Level, cfg.Log.Format)
			app := daemon.New(cfg, log)
			return app.Run(context.Background())
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "path to config file")
	return cmd
}

func newLogger(level, format string) *slog.Logger {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	if strings.ToLower(format) == "text" {
		h = slog.NewTextHandler(os.Stdout, opts)
	} else {
		h = slog.NewJSONHandler(os.Stdout, opts)
	}
	return slog.New(h)
}
