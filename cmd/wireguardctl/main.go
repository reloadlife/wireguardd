package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/reloadlife/wireguardd/internal/config"
	"github.com/reloadlife/wireguardd/internal/tui"
	"github.com/reloadlife/wireguardd/internal/version"
	pkgapi "github.com/reloadlife/wireguardd/pkg/api"
)

func main() {
	var configPath string
	root := &cobra.Command{
		Use:   "wireguardctl",
		Short: "WireGuard control panel (TUI + CLI)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(configPath)
		},
	}
	root.PersistentFlags().StringVar(&configPath, "config", "", "path to config file")
	root.AddCommand(
		versionCmd(),
		ifaceCmd(&configPath),
		peerCmd(&configPath),
		statsCmd(&configPath),
		eventsCmd(&configPath),
		keysCmd(&configPath),
		tuiCmd(&configPath),
	)
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

func tuiCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "tui",
		Short: "Open interactive TUI",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runTUI(*configPath)
		},
	}
}

func runTUI(configPath string) error {
	cfg, client, err := loadClient(configPath)
	if err != nil {
		return err
	}
	return tui.Run(tui.Config{
		Client:          client,
		Endpoint:        cfg.Endpoint(),
		RefreshInterval: cfg.Refresh(),
	})
}

func loadClient(configPath string) (*config.CtlConfig, *pkgapi.Client, error) {
	cfg, err := config.LoadCtl(configPath)
	if err != nil {
		return nil, nil, err
	}
	client, err := pkgapi.NewClient(cfg.Endpoint(), pkgapi.WithToken(cfg.Server.Token))
	if err != nil {
		return nil, nil, err
	}
	return cfg, client, nil
}

func ifaceCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "iface", Short: "Interface operations"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list",
		Short: "List interfaces",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			list, err := c.ListInterfaces(ctx)
			if err != nil {
				return err
			}
			return printJSON(list)
		},
	})
	var create pkgapi.InterfaceCreateRequest
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create interface",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			out, err := c.CreateInterface(ctx, create)
			if err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	createCmd.Flags().StringVar(&create.Name, "name", "", "interface name (required)")
	createCmd.Flags().IntVar(&create.ListenPort, "port", 51820, "listen port")
	createCmd.Flags().StringSliceVar(&create.Addresses, "address", nil, "address CIDR (repeatable)")
	createCmd.Flags().StringSliceVar(&create.DNS, "dns", nil, "DNS servers")
	_ = createCmd.MarkFlagRequired("name")
	cmd.AddCommand(createCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "up [name]",
		Short: "Bring interface up",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			return c.InterfaceUp(context.Background(), args[0])
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "down [name]",
		Short: "Bring interface down",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			return c.InterfaceDown(context.Background(), args[0])
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete [name]",
		Short: "Delete interface",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			return c.DeleteInterface(context.Background(), args[0])
		},
	})
	return cmd
}

func peerCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "peer", Short: "Peer operations"}
	cmd.AddCommand(&cobra.Command{
		Use:   "list [iface]",
		Short: "List peers (optional iface)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			ctx := context.Background()
			var list []pkgapi.Peer
			if len(args) == 1 {
				list, err = c.ListPeers(ctx, args[0])
			} else {
				list, err = c.ListAllPeers(ctx)
			}
			if err != nil {
				return err
			}
			return printJSON(list)
		},
	})
	var create pkgapi.PeerCreateRequest
	var ifaceName string
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "Create peer",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			out, err := c.CreatePeer(context.Background(), ifaceName, create)
			if err != nil {
				return err
			}
			return printJSON(out)
		},
	}
	createCmd.Flags().StringVar(&ifaceName, "iface", "", "interface name")
	createCmd.Flags().StringVar(&create.PublicKey, "pubkey", "", "peer public key")
	createCmd.Flags().StringVar(&create.Name, "name", "", "friendly name")
	createCmd.Flags().StringSliceVar(&create.AllowedIPs, "allowed-ip", nil, "allowed IPs")
	createCmd.Flags().StringVar(&create.Endpoint, "endpoint", "", "endpoint host:port")
	createCmd.Flags().BoolVar(&create.GeneratePSK, "psk", false, "generate preshared key")
	_ = createCmd.MarkFlagRequired("iface")
	_ = createCmd.MarkFlagRequired("pubkey")
	cmd.AddCommand(createCmd)

	cmd.AddCommand(&cobra.Command{
		Use:   "suspend [iface] [pubkey]",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			return c.SuspendPeer(context.Background(), args[0], args[1])
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "resume [iface] [pubkey]",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			return c.ResumePeer(context.Background(), args[0], args[1])
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "delete [iface] [pubkey]",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			return c.DeletePeer(context.Background(), args[0], args[1])
		},
	})
	return cmd
}

func statsCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "stats",
		Short: "Show global stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			s, err := c.Stats(context.Background())
			if err != nil {
				return err
			}
			return printJSON(s)
		},
	}
}

func eventsCmd(configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "events",
		Short: "List recent events",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			ev, err := c.ListEvents(context.Background())
			if err != nil {
				return err
			}
			return printJSON(ev)
		},
	}
}

func keysCmd(configPath *string) *cobra.Command {
	cmd := &cobra.Command{Use: "keys", Short: "Key generation"}
	cmd.AddCommand(&cobra.Command{
		Use:   "gen",
		Short: "Generate keypair",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			k, err := c.GenerateKeys(context.Background(), "keypair")
			if err != nil {
				return err
			}
			return printJSON(k)
		},
	})
	cmd.AddCommand(&cobra.Command{
		Use:   "psk",
		Short: "Generate preshared key",
		RunE: func(cmd *cobra.Command, args []string) error {
			_, c, err := loadClient(*configPath)
			if err != nil {
				return err
			}
			k, err := c.GenerateKeys(context.Background(), "preshared")
			if err != nil {
				return err
			}
			return printJSON(k)
		},
	})
	return cmd
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
