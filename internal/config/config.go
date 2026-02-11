package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

// Config holds all application configuration.
type Config struct {
	Server   ServerConfig   `yaml:"server"`
	Sandbox  SandboxConfig  `yaml:"sandbox"`
	Database DatabaseConfig `yaml:"database"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Tracing  TracingConfig  `yaml:"tracing"`
	Security SecurityConfig `yaml:"security"`
	Pool     PoolConfig     `yaml:"pool"`
	TLS      TLSConfig      `yaml:"tls"`
}

type ServerConfig struct {
	Host            string        `yaml:"host"`
	Port            int           `yaml:"port"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout"`
	MaxRequestBody  int64         `yaml:"max_request_body_bytes"`
}

type SandboxConfig struct {
	ContainerdSocket    string        `yaml:"containerd_socket"`
	Namespace           string        `yaml:"namespace"`
	DefaultTimeout      time.Duration `yaml:"default_timeout"`
	MaxTimeout          time.Duration `yaml:"max_timeout"`
	MaxConcurrent       int           `yaml:"max_concurrent"`
	DefaultLimits       DefaultLimits `yaml:"default_limits"`
	Backend             string        `yaml:"backend"`              // "auto" (default), "containerd", or "docker"
	AllowedWorkdirRoots []string      `yaml:"allowed_workdir_roots"` // Absolute paths that WorkDir must be under; empty blocks all WorkDir mounts
}

type DefaultLimits struct {
	CPUShares int64 `yaml:"cpu_shares"`
	MemoryMB  int64 `yaml:"memory_mb"`
	PidsLimit int64 `yaml:"pids_limit"`
	DiskMB    int64 `yaml:"disk_mb"`
}

type DatabaseConfig struct {
	DSN             string        `yaml:"dsn"`
	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Path    string `yaml:"path"`
}

type TracingConfig struct {
	Enabled  bool    `yaml:"enabled"`
	Endpoint string  `yaml:"endpoint"`
	Sample   float64 `yaml:"sample_rate"`
}

type SecurityConfig struct {
	APIKeyHeader   string   `yaml:"api_key_header"`
	AllowedKeys    []string `yaml:"allowed_keys"`
	RateLimitRPS   float64  `yaml:"rate_limit_rps"`
	RateLimitBurst int      `yaml:"rate_limit_burst"`
	SeccompProfile string   `yaml:"seccomp_profile"`
}

// PoolConfig controls pre-warmed container pooling.
type PoolConfig struct {
	Enabled     bool          `yaml:"enabled"`
	MinIdle     int           `yaml:"min_idle"`
	MaxIdle     int           `yaml:"max_idle"`
	RefillDelay time.Duration `yaml:"refill_delay"`
	MaxAge      time.Duration `yaml:"max_age"`
}

// TLSConfig controls HTTPS/TLS termination.
type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Load reads configuration from a YAML file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- path comes from CLI flag or hardcoded default
	if err != nil {
		return nil, fmt.Errorf("reading config file: %w", err)
	}

	cfg := DefaultConfig()
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return cfg, nil
}

// DefaultConfig returns sensible defaults for all configuration.
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    65 * time.Second, // > max sandbox timeout + overhead
			ShutdownTimeout: 30 * time.Second,
			MaxRequestBody:  1 << 20, // 1MB
		},
		Sandbox: SandboxConfig{
			ContainerdSocket: "/run/containerd/containerd.sock",
			Namespace:        "sandbox",
			DefaultTimeout:   10 * time.Second,
			MaxTimeout:       60 * time.Second,
			MaxConcurrent:    1000,
			Backend:          "auto",
			DefaultLimits: DefaultLimits{
				CPUShares: 512,
				MemoryMB:  256,
				PidsLimit: 50,
				DiskMB:    100,
			},
		},
		Database: DatabaseConfig{
			DSN:             "",
			MaxOpenConns:    25,
			MaxIdleConns:    5,
			ConnMaxLifetime: 5 * time.Minute,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Path:    "/metrics",
		},
		Tracing: TracingConfig{
			Enabled: false,
			Sample:  0.1,
		},
		Security: SecurityConfig{
			APIKeyHeader:   "X-API-Key",
			RateLimitRPS:   100,
			RateLimitBurst: 200,
		},
		Pool: PoolConfig{
			Enabled:     true,
			MinIdle:     2,
			MaxIdle:     10,
			RefillDelay: 500 * time.Millisecond,
			MaxAge:      5 * time.Minute,
		},
		TLS: TLSConfig{
			Enabled: false,
		},
	}
}

// Validate checks that the configuration is valid.
func (c *Config) Validate() error {
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be 1-65535, got %d", c.Server.Port)
	}
	if c.Sandbox.DefaultTimeout > c.Sandbox.MaxTimeout {
		return fmt.Errorf("sandbox.default_timeout (%s) must be <= max_timeout (%s)",
			c.Sandbox.DefaultTimeout, c.Sandbox.MaxTimeout)
	}
	if c.Sandbox.MaxConcurrent < 1 {
		return fmt.Errorf("sandbox.max_concurrent must be >= 1")
	}
	if c.Sandbox.DefaultLimits.MemoryMB < 16 {
		return fmt.Errorf("sandbox.default_limits.memory_mb must be >= 16")
	}
	if c.TLS.Enabled {
		if c.TLS.CertFile == "" || c.TLS.KeyFile == "" {
			return fmt.Errorf("tls.cert_file and tls.key_file are required when TLS is enabled")
		}
	}
	for _, root := range c.Sandbox.AllowedWorkdirRoots {
		if !filepath.IsAbs(root) {
			return fmt.Errorf("sandbox.allowed_workdir_roots: %q must be an absolute path", root)
		}
	}
	if c.Database.DSN != "" && strings.Contains(c.Database.DSN, "sslmode=disable") {
		log.Warn().Msg("database DSN has sslmode=disable — connections to Postgres are unencrypted")
	}
	return nil
}

// Address returns the listen address string.
func (c *Config) Address() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}
