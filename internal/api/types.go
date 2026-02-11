package api

import "time"

// ExecutionRequest is the API-level request to execute code in a sandbox.
type ExecutionRequest struct {
	Code     string         `json:"code"`
	Language string         `json:"language"` // python, node, bash, claude
	Timeout  Duration       `json:"timeout,omitempty"`
	Limits   ResourceLimits `json:"limits,omitempty"`
	Perms    Permissions    `json:"permissions,omitempty"`
	WorkDir  string         `json:"work_dir,omitempty"` // Host directory to mount (claude runtime)
}

// Duration wraps time.Duration for JSON marshaling as a string like "10s".
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	dur, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = dur
	return nil
}

// ResourceLimits defines sandbox resource constraints.
type ResourceLimits struct {
	CPUShares int64 `json:"cpu_shares,omitempty"` // 1024 = 1 CPU
	MemoryMB  int64 `json:"memory_mb,omitempty"`
	PidsLimit int64 `json:"pids_limit,omitempty"`
	DiskMB    int64 `json:"disk_mb,omitempty"`
}

// Permissions defines what the sandboxed code is allowed to access.
type Permissions struct {
	Network     NetworkPermissions    `json:"network,omitempty"`
	Filesystem  FilesystemPermissions `json:"filesystem,omitempty"`
	Environment []string              `json:"environment,omitempty"`
}

// NetworkPermissions controls network access within the sandbox.
type NetworkPermissions struct {
	Enabled      bool     `json:"enabled"`
	AllowedHosts []string `json:"allowed_hosts,omitempty"`
	AllowedPorts []int    `json:"allowed_ports,omitempty"`
}

// FilesystemPermissions controls filesystem access.
type FilesystemPermissions struct {
	ReadOnly     bool     `json:"read_only"`
	WritableDirs []string `json:"writable_dirs,omitempty"`
}

// ExecutionResponse is the API-level response after sandbox execution.
type ExecutionResponse struct {
	ID             string          `json:"id"`
	Output         string          `json:"output"`
	Stderr         string          `json:"stderr"`
	ExitCode       int             `json:"exit_code"`
	Duration       string          `json:"duration"`
	ResourceUsage  ResourceUsage   `json:"resource_usage"`
	SecurityEvents []SecurityEvent `json:"security_events,omitempty"`
	Cached         bool            `json:"cached,omitempty"`
}

// ResourceUsage reports measured resource consumption.
type ResourceUsage struct {
	CPUTimeMS    int64 `json:"cpu_time_ms"`
	MemoryPeakMB int64 `json:"memory_peak_mb"`
	PidsUsed     int64 `json:"pids_used"`
}

// SecurityEvent records suspicious activity during execution.
type SecurityEvent struct {
	Type    string `json:"type"`
	Syscall string `json:"syscall,omitempty"`
	Detail  string `json:"detail"`
}

// ErrorResponse is returned for API errors.
type ErrorResponse struct {
	Error     string `json:"error"`
	Code      string `json:"code"`
	RequestID string `json:"request_id"`
}

// HealthResponse is returned by the health check endpoint.
type HealthResponse struct {
	Status     string `json:"status"`
	Containerd bool   `json:"containerd"`
	Database   bool   `json:"database"`
	Uptime     string `json:"uptime"`
}
