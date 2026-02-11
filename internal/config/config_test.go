package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want 8080", cfg.Server.Port)
	}
	if cfg.AuthProxy.Port != 0 {
		t.Errorf("AuthProxy.Port = %d, want 0 (disabled)", cfg.AuthProxy.Port)
	}
	if cfg.Sandbox.MaxConcurrent != 1000 {
		t.Errorf("Sandbox.MaxConcurrent = %d, want 1000", cfg.Sandbox.MaxConcurrent)
	}
	if cfg.Sandbox.DefaultTimeout != 10*time.Second {
		t.Errorf("Sandbox.DefaultTimeout = %s, want 10s", cfg.Sandbox.DefaultTimeout)
	}
	if cfg.Sandbox.DefaultLimits.MemoryMB != 256 {
		t.Errorf("DefaultLimits.MemoryMB = %d, want 256", cfg.Sandbox.DefaultLimits.MemoryMB)
	}
}

func TestValidate(t *testing.T) {
	valid := func() *Config {
		return DefaultConfig()
	}

	tests := []struct {
		name    string
		modify  func(*Config)
		wantErr bool
	}{
		{"valid defaults", func(c *Config) {}, false},
		{"server port 0", func(c *Config) { c.Server.Port = 0 }, true},
		{"server port 99999", func(c *Config) { c.Server.Port = 99999 }, true},
		{"default_timeout > max_timeout", func(c *Config) {
			c.Sandbox.DefaultTimeout = 2 * time.Minute
			c.Sandbox.MaxTimeout = 1 * time.Minute
		}, true},
		{"max_concurrent 0", func(c *Config) { c.Sandbox.MaxConcurrent = 0 }, true},
		{"memory_mb < 16", func(c *Config) { c.Sandbox.DefaultLimits.MemoryMB = 8 }, true},
		{"TLS enabled without cert", func(c *Config) {
			c.TLS.Enabled = true
			c.TLS.CertFile = ""
			c.TLS.KeyFile = ""
		}, true},
		{"TLS enabled with cert+key", func(c *Config) {
			c.TLS.Enabled = true
			c.TLS.CertFile = "/etc/ssl/cert.pem"
			c.TLS.KeyFile = "/etc/ssl/key.pem"
		}, false},
		{"auth_proxy port -1", func(c *Config) { c.AuthProxy.Port = -1 }, true},
		{"auth_proxy port 70000", func(c *Config) { c.AuthProxy.Port = 70000 }, true},
		{"auth_proxy port 8081", func(c *Config) { c.AuthProxy.Port = 8081 }, false},
		{"relative workdir root", func(c *Config) {
			c.Sandbox.AllowedWorkdirRoots = []string{"relative/path"}
		}, true},
		{"absolute workdir root", func(c *Config) {
			c.Sandbox.AllowedWorkdirRoots = []string{"/tmp/sandbox"}
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			tt.modify(cfg)
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad(t *testing.T) {
	yamlContent := `
server:
  host: "127.0.0.1"
  port: 9090
sandbox:
  max_concurrent: 50
  default_timeout: 15s
  max_timeout: 120s
  default_limits:
    memory_mb: 512
auth_proxy:
  port: 8081
`
	tmpFile, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if _, err := tmpFile.WriteString(yamlContent); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	cfg, err := Load(tmpFile.Name())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Host != "127.0.0.1" {
		t.Errorf("Server.Host = %q, want %q", cfg.Server.Host, "127.0.0.1")
	}
	if cfg.Server.Port != 9090 {
		t.Errorf("Server.Port = %d, want 9090", cfg.Server.Port)
	}
	if cfg.Sandbox.MaxConcurrent != 50 {
		t.Errorf("Sandbox.MaxConcurrent = %d, want 50", cfg.Sandbox.MaxConcurrent)
	}
	if cfg.Sandbox.DefaultTimeout != 15*time.Second {
		t.Errorf("Sandbox.DefaultTimeout = %s, want 15s", cfg.Sandbox.DefaultTimeout)
	}
	if cfg.Sandbox.DefaultLimits.MemoryMB != 512 {
		t.Errorf("DefaultLimits.MemoryMB = %d, want 512", cfg.Sandbox.DefaultLimits.MemoryMB)
	}
	if cfg.AuthProxy.Port != 8081 {
		t.Errorf("AuthProxy.Port = %d, want 8081", cfg.AuthProxy.Port)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "nonexistent.yaml"))
	if err == nil {
		t.Error("expected error for missing file, got nil")
	}
}

func TestAddress(t *testing.T) {
	cfg := DefaultConfig()
	want := "0.0.0.0:8080"
	if got := cfg.Address(); got != want {
		t.Errorf("Address() = %q, want %q", got, want)
	}

	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = 3000
	want = "127.0.0.1:3000"
	if got := cfg.Address(); got != want {
		t.Errorf("Address() = %q, want %q", got, want)
	}
}
