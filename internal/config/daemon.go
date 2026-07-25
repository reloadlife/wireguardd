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
		Path           string `mapstructure:"path"`
		TimeseriesPath string `mapstructure:"timeseries_path"` // empty → <dir>/timeseries.db
		// MemoryProfile selects SQLite page-cache + mmap budgets:
		//   compact (default) | balanced | performance
		// Explicit *_cache_mb / *_mmap_mb override the profile when > 0.
		MemoryProfile     string `mapstructure:"memory_profile"`
		StateCacheMB      int    `mapstructure:"state_cache_mb"`
		StateMMapMB       int    `mapstructure:"state_mmap_mb"`
		TimeseriesCacheMB int    `mapstructure:"timeseries_cache_mb"`
		TimeseriesMMapMB  int    `mapstructure:"timeseries_mmap_mb"`
	} `mapstructure:"db"`
	Auth struct {
		Token string `mapstructure:"token"`
	} `mapstructure:"auth"`
	WireGuard struct {
		ConfDir               string `mapstructure:"conf_dir"`
		Persistence           string `mapstructure:"persistence"`
		HandshakeConnectedSec int    `mapstructure:"handshake_connected_sec"`
		SampleInterval        string `mapstructure:"sample_interval"`
		// SampleRetention is how long traffic_samples are kept (default 24h).
		SampleRetention   string `mapstructure:"sample_retention"`
		ReconcileInterval string `mapstructure:"reconcile_interval"`
		AllowHooks        bool   `mapstructure:"allow_hooks"`
		BandwidthBackend  string `mapstructure:"bandwidth_backend"`
		DNSBackend        string `mapstructure:"dns_backend"` // auto | resolvectl | resolvconf | none
		UseMockBackend    bool   `mapstructure:"use_mock_backend"`
		// AdoptOnStart imports live WireGuard devices into the DB on boot (non-destructive).
		AdoptOnStart bool `mapstructure:"adopt_on_start"`
		// Optional binary overrides (empty → PATH: wireguard-go / amneziawg-go / awg).
		WireGuardGo string `mapstructure:"wireguard_go"`
		AmneziaWGGo string `mapstructure:"amneziawg_go"`
		AWGTool     string `mapstructure:"awg_tool"`
	} `mapstructure:"wireguard"`
	Log struct {
		Level  string `mapstructure:"level"`
		Format string `mapstructure:"format"`
	} `mapstructure:"log"`
	ReadOnly bool `mapstructure:"read_only"`
	// Webhooks push agent events to an external controller (optional).
	Webhooks WebhooksConfig `mapstructure:"webhooks"`
}

// WebhooksConfig delivers HTTP callbacks for controller integration.
type WebhooksConfig struct {
	Enabled   bool     `mapstructure:"enabled" yaml:"enabled"`
	URL       string   `mapstructure:"url" yaml:"url"`
	Secret    string   `mapstructure:"secret" yaml:"secret"`
	Events    []string `mapstructure:"events" yaml:"events"`
	Timeout   string   `mapstructure:"timeout" yaml:"timeout"`
	QueueSize int      `mapstructure:"queue_size" yaml:"queue_size"`
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
	_ = v.BindEnv("db.timeseries_path", "WIREGUARDD_DB_TIMESERIES_PATH")
	_ = v.BindEnv("db.memory_profile", "WIREGUARDD_DB_MEMORY_PROFILE")
	_ = v.BindEnv("listen.http", "WIREGUARDD_LISTEN_HTTP")

	var cfg DaemonConfig
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	if cfg.Auth.Token == "" {
		cfg.Auth.Token = v.GetString("auth.token")
	}
	cfg.WireGuard.BandwidthBackend = strings.ToLower(strings.TrimSpace(cfg.WireGuard.BandwidthBackend))
	switch cfg.WireGuard.BandwidthBackend {
	case "", "tc", "nft", "none":
		if cfg.WireGuard.BandwidthBackend == "" {
			cfg.WireGuard.BandwidthBackend = "tc"
		}
	default:
		return nil, fmt.Errorf("wireguard.bandwidth_backend %q invalid (want tc|nft|none)", cfg.WireGuard.BandwidthBackend)
	}
	cfg.WireGuard.DNSBackend = strings.ToLower(strings.TrimSpace(cfg.WireGuard.DNSBackend))
	cfg.DB.MemoryProfile = strings.ToLower(strings.TrimSpace(cfg.DB.MemoryProfile))
	switch cfg.DB.MemoryProfile {
	case "", "compact", "balanced", "performance":
		if cfg.DB.MemoryProfile == "" {
			cfg.DB.MemoryProfile = "compact"
		}
	default:
		return nil, fmt.Errorf("db.memory_profile %q invalid (want compact|balanced|performance)", cfg.DB.MemoryProfile)
	}
	return &cfg, nil
}

func setDaemonDefaults(v *viper.Viper) {
	v.SetDefault("listen.http", "127.0.0.1:51880")
	v.SetDefault("listen.unix", "")
	v.SetDefault("listen.metrics", "127.0.0.1:9091")
	v.SetDefault("snmp.enabled", false)
	v.SetDefault("snmp.listen", "127.0.0.1:1161")
	v.SetDefault("snmp.community", "change-me-snmp")
	v.SetDefault("snmp.enterprise_oid", "1.3.6.1.4.1.66666.1")
	v.SetDefault("db.path", "wireguardd.db")
	v.SetDefault("db.memory_profile", "compact")
	v.SetDefault("auth.token", "change-me")
	v.SetDefault("wireguard.conf_dir", "/etc/wireguard")
	v.SetDefault("wireguard.persistence", "hybrid")
	v.SetDefault("wireguard.handshake_connected_sec", 180)
	v.SetDefault("wireguard.sample_interval", "5s")
	v.SetDefault("wireguard.sample_retention", "24h")
	v.SetDefault("wireguard.reconcile_interval", "5s")
	v.SetDefault("wireguard.allow_hooks", false)
	v.SetDefault("wireguard.bandwidth_backend", "tc")
	v.SetDefault("wireguard.dns_backend", "auto")
	v.SetDefault("wireguard.use_mock_backend", false)
	v.SetDefault("wireguard.adopt_on_start", false)
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "json")
	v.SetDefault("read_only", false)
	v.SetDefault("webhooks.enabled", false)
	v.SetDefault("webhooks.url", "")
	v.SetDefault("webhooks.secret", "")
	v.SetDefault("webhooks.timeout", "5s")
	v.SetDefault("webhooks.queue_size", 256)
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

// SampleRetention parses how long traffic samples are kept.
func (c *DaemonConfig) SampleRetention() time.Duration {
	d, err := time.ParseDuration(c.WireGuard.SampleRetention)
	if err != nil || d <= 0 {
		return 24 * time.Hour
	}
	return d
}

// StateSQLiteMem returns the page-cache/mmap budget for state.db.
func (c *DaemonConfig) StateSQLiteMem() (cacheMiB, mmapMiB int) {
	cacheMiB, mmapMiB = profileMem(c.DB.MemoryProfile, false)
	if c.DB.StateCacheMB > 0 {
		cacheMiB = c.DB.StateCacheMB
	}
	if c.DB.StateMMapMB > 0 {
		mmapMiB = c.DB.StateMMapMB
	}
	return cacheMiB, mmapMiB
}

// TimeseriesSQLiteMem returns the page-cache/mmap budget for timeseries.db.
func (c *DaemonConfig) TimeseriesSQLiteMem() (cacheMiB, mmapMiB int) {
	cacheMiB, mmapMiB = profileMem(c.DB.MemoryProfile, true)
	if c.DB.TimeseriesCacheMB > 0 {
		cacheMiB = c.DB.TimeseriesCacheMB
	}
	if c.DB.TimeseriesMMapMB > 0 {
		mmapMiB = c.DB.TimeseriesMMapMB
	}
	return cacheMiB, mmapMiB
}

func profileMem(profile string, timeseries bool) (cacheMiB, mmapMiB int) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "performance":
		if timeseries {
			return 128, 512
		}
		return 64, 256
	case "balanced":
		return 32, 128
	default: // compact
		if timeseries {
			return 16, 64
		}
		return 16, 64
	}
}
