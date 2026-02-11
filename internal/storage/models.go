package storage

import "time"

// Execution represents a stored execution record.
type Execution struct {
	ID             string    `json:"id" db:"id"`
	Language       string    `json:"language" db:"language"`
	CodeHash       string    `json:"code_hash" db:"code_hash"`
	ExitCode       int       `json:"exit_code" db:"exit_code"`
	Output         string    `json:"output" db:"output"`
	Stderr         string    `json:"stderr" db:"stderr"`
	DurationMS     int64     `json:"duration_ms" db:"duration_ms"`
	CPUTimeMS      int64     `json:"cpu_time_ms" db:"cpu_time_ms"`
	MemoryPeakMB   int64     `json:"memory_peak_mb" db:"memory_peak_mb"`
	SecurityEvents int       `json:"security_events" db:"security_events"`
	Status         string    `json:"status" db:"status"` // running, completed, timeout, error, killed
	RequestIP      string    `json:"request_ip" db:"request_ip"`
	APIKeyHash     string    `json:"api_key_hash,omitempty" db:"api_key_hash"`
	CreatedAt      time.Time `json:"created_at" db:"created_at"`
	CompletedAt    *time.Time `json:"completed_at,omitempty" db:"completed_at"`
}

// SecurityEventRecord stores security event details for audit.
type SecurityEventRecord struct {
	ID          string    `json:"id" db:"id"`
	ExecutionID string    `json:"execution_id" db:"execution_id"`
	Type        string    `json:"type" db:"type"`
	Severity    string    `json:"severity" db:"severity"`
	Detail      string    `json:"detail" db:"detail"`
	Syscall     string    `json:"syscall,omitempty" db:"syscall"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// ExecutionFilter provides criteria for querying executions.
type ExecutionFilter struct {
	Language   string
	Status     string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}
