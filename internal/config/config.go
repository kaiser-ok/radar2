package config

import (
	"time"

	"github.com/spf13/viper"
)

type Config struct {
	Server    ServerConfig    `mapstructure:"server"`
	Auth      AuthConfig      `mapstructure:"auth"`
	Database  DatabaseConfig  `mapstructure:"database"`
	SNMP      SNMPConfig      `mapstructure:"snmp"`
	Task      TaskConfig      `mapstructure:"task"`
	Discovery DiscoveryConfig `mapstructure:"discovery"`
	RSPAN     RSPANConfig     `mapstructure:"rspan"`
	Version   string          `mapstructure:"version"`
	BuildDate string          `mapstructure:"build_date"`
}

type ServerConfig struct {
	Port         int           `mapstructure:"port"`
	ReadTimeout  time.Duration `mapstructure:"read_timeout"`
	WriteTimeout time.Duration `mapstructure:"write_timeout"`
}

type AuthConfig struct {
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
}

type DatabaseConfig struct {
	Path string `mapstructure:"path"`
}

type SNMPConfig struct {
	Timeout          time.Duration `mapstructure:"timeout"`
	Retries          int           `mapstructure:"retries"`
	MaxOIDsPerReq    int           `mapstructure:"max_oids_per_request"`
	OIDFile          string        `mapstructure:"oid_file"`
}

type TaskConfig struct {
	CleanupInterval time.Duration `mapstructure:"cleanup_interval"`
	MaxAge          time.Duration `mapstructure:"max_age"`
}

type DiscoveryConfig struct {
	Timeout           time.Duration `mapstructure:"timeout"`
	ConcurrentWorkers int           `mapstructure:"concurrent_workers"`
}

type RSPANConfig struct {
	Interface  string `mapstructure:"interface"`
	PcapDir    string `mapstructure:"pcap_dir"`
	MaxPcapSize string `mapstructure:"max_pcap_size"`
	MaxPcapAge string `mapstructure:"max_pcap_age"`
	BPFFilter  string `mapstructure:"bpf_filter"`
}

func Load(path string) (*Config, error) {
	viper.SetConfigFile(path)
	viper.SetConfigType("yaml")

	// Environment variable overrides
	viper.SetEnvPrefix("RADAR")
	viper.AutomaticEnv()

	// Bind specific env vars
	viper.BindEnv("auth.username", "RADAR_API_USER")
	viper.BindEnv("auth.password", "RADAR_API_PASSWORD")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}

	// Defaults
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 8082
	}
	if cfg.Server.ReadTimeout == 0 {
		cfg.Server.ReadTimeout = 15 * time.Second
	}
	if cfg.Server.WriteTimeout == 0 {
		cfg.Server.WriteTimeout = 60 * time.Second
	}
	if cfg.SNMP.Timeout == 0 {
		cfg.SNMP.Timeout = 5 * time.Second
	}
	if cfg.SNMP.Retries == 0 {
		cfg.SNMP.Retries = 1
	}
	if cfg.Task.CleanupInterval == 0 {
		cfg.Task.CleanupInterval = 5 * time.Minute
	}
	if cfg.Task.MaxAge == 0 {
		cfg.Task.MaxAge = 30 * time.Minute
	}

	return &cfg, nil
}
