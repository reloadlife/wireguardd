package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// DaemonConfig holds wireguardd configuration.
type DaemonConfig struct {
	Listen struct {
		HTTP    string `mapstructure:"http"`
		Unix    string `mapstructure:"unix"`
		Metrics string `mapstructure:"metrics"`
	} `mapstructure:"listen"`
	SNMP struct {
		Enabled       bool   `mapstructure:"enabled"`
		Listen        string `mapstructure:"listen"`
		Community     string `mapstructure:"community"`
		EnterpriseOID string `mapstructure:"enterprise_oid"`
	} `mapstructure:"snmp"`
	DB struct {
		Path string `mapstructure:"path"`
	} `mapstructure:"db"`
	Auth struct {
		Token string `mapstructure:"token"`
	} `mapstructure:"auth"`
	WireGuard struct {
		ConfDir               string `mapstructure:"conf_dir"`
		Persistence           string `mapstructure:"persistence"`
		HandshakeConnectedSec int    `mapstructure:"handshake_connected_sec"`
		SampleInterval        string `mapstructure:"sample_interval"`
		ReconcileInterval     string `mapstructure:"reconcile_interval"`
		AllowHooks            bool   `mapstructure:"allow_hooks"`
		BandwidthBackend      string `mapstructure:"bandwidth_backend"`
		UseMockBackend        bool   `mapstructure:"use_mock_backend"`
	} `mapstructure:"wireguard"`
	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
	ReadOnly bool `mapstructure:"read_only"`
}

// LoadDaemon loads daemon config from file/env/defaults.
func LoadDaemon(path string) (*DaemonConfig, error) {
	v := viper.New()
	v.SetConfigType("yaml")
	v.SetEnvPrefix("WIREGUARDD")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	setDaemonDefaults(v)

	if path != "" {
		v.SetConfigFile(path)
		if err := v.ReadInConfig(); err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	// Flat env bindings for common keys
	_ = v.BindEnv("auth.token", "WIREGUARDD_AUTH_TOKEN", "WIREGUARDD_API_TOKEN")
	_ = v.BindEnv("db.path", "WIREGUARDD_DB_PATH")
	_ = v.BindEnv("listen.http", "WIREGUARDD_LISTEN_HTTP")

	var cfg DaemonConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	if cfg.Auth.Token == "" {
		cfg.Auth.Token = v.GetString("auth.token")
	}
	return &cfg, nil
}

func setDaemonDefaults(v *viper.Viper) {
	v.SetDefault("listen.http", "127.0.0.1:51880")
	v.SetDefault("listen.unix", "")
	v.SetDefault("listen.metrics", "0.0.0.0:9091")
	v.SetDefault("snmp.enabled", true)
	v.SetDefault("snmp.listen", "0.0.0.0:1161")
	v.SetDefault("snmp.community", "public")
	v.SetDefault("snmp.enterprise_oid", "1.3.6.1.4.1.66666.1")
	v.SetDefault("db.path", "wireguardd.db")
	v.SetDefault("auth.token", "change-me")
	v.SetDefault("wireguard.conf_dir", "/etc/wireguard")
	v.SetDefault("wireguard.persistence", "hybrid")
	v.SetDefault("wireguard.handshake_connected_sec", 180)
	v.SetDefault("wireguard.sample_interval", "5s")
	v.SetDefault("wireguard.reconcile_interval", "5s")
	v.SetDefault("wireguard.allow_hooks", false)
	v.SetDefault("wireguard.bandwidth_backend", "tc")
	v.SetDefault("wireguard.use_mock_backend", false)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("read_only", false)
}

// ReconcileInterval parses duration.
func (c *DaemonConfig) ReconcileInterval() time.Duration {
	d, err := time.ParseDuration(c.WireGuard.ReconcileInterval)
	if err != nil {
		return 5 * time.Second
	}
	return d
}

// SampleInterval parses duration.
func (c *DaemonConfig) SampleInterval() time.Duration {
	d, err := time.ParseDuration(c.WireGuard.SampleInterval)
	if err != nil {
		return 5 * time.Second
	}
	return d
}
