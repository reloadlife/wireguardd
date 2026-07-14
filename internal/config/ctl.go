package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// CtlConfig holds wireguardctl configuration.
type CtlConfig struct {
	Server struct {
		URL   string `mapstructure:"url"`
		Unix  string `mapstructure:"unix"`
		Token string `mapstructure:"token"`
	} `mapstructure:"server"`
	RefreshInterval string `mapstructure:"refresh_interval"`
}

// LoadCtl loads ctl config.
func LoadCtl(path string) (*CtlConfig, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("WIREGUARDCTL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	v.SetDefault("server.url", "http://127.0.0.1:51880")
	v.SetDefault("server.unix", "")
	v.SetDefault("server.token", "change-me")
	v.SetDefault("refresh_interval", "2s")

	if path == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cand := filepath.Join(home, ".config", "wireguardctl", "config.yaml")
			if _, err := os.Stat(cand); err == nil {
				path = cand
			}
		}
	}
	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}
	_ = v.BindEnv("server.token", "WIREGUARDCTL_TOKEN", "WIREGUARDD_AUTH_TOKEN")
	_ = v.BindEnv("server.url", "WIREGUARDCTL_URL")
	_ = v.BindEnv("server.unix", "WIREGUARDCTL_UNIX")

	var cfg CtlConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Refresh returns refresh duration.
func (c *CtlConfig) Refresh() time.Duration {
	d, err := time.ParseDuration(c.RefreshInterval)
	if err != nil {
		return 2 * time.Second
	}
	return d
}

// Endpoint returns connection string for the client.
func (c *CtlConfig) Endpoint() string {
	if c.Server.Unix != "" {
		return "unix://" + c.Server.Unix
	}
	return c.Server.URL
}
