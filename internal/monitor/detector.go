package monitor

import (
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
)

// EscapeDetector analyzes code and execution output for escape attempts.
// This provides an additional layer of detection beyond seccomp/capabilities.
type EscapeDetector struct {
	patterns []DetectionPattern
}

// DetectionPattern defines a suspicious pattern to match.
type DetectionPattern struct {
	Name        string
	Description string
	Regex       *regexp.Regexp
	Severity    Severity
}

// Severity levels for detected threats.
type Severity int

const (
	SeverityLow Severity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// Detection represents a detected suspicious pattern.
type Detection struct {
	Pattern  string   `json:"pattern"`
	Severity string   `json:"severity"`
	Detail   string   `json:"detail"`
	Line     int      `json:"line,omitempty"`
}

// NewEscapeDetector creates a detector with default patterns.
func NewEscapeDetector() *EscapeDetector {
	return &EscapeDetector{
		patterns: defaultPatterns(),
	}
}

// AnalyzeCode checks submitted code for suspicious patterns before execution.
func (d *EscapeDetector) AnalyzeCode(code string) []Detection {
	var detections []Detection

	lines := strings.Split(code, "\n")
	for i, line := range lines {
		for _, p := range d.patterns {
			if p.Regex.MatchString(line) {
				det := Detection{
					Pattern:  p.Name,
					Severity: p.Severity.String(),
					Detail:   p.Description,
					Line:     i + 1,
				}
				detections = append(detections, det)

				log.Warn().
					Str("pattern", p.Name).
					Str("severity", p.Severity.String()).
					Int("line", i+1).
					Msg("escape attempt detected in code")
			}
		}
	}

	return detections
}

// AnalyzeOutput checks execution output for signs of successful escape.
func (d *EscapeDetector) AnalyzeOutput(output string) []Detection {
	var detections []Detection

	outputPatterns := []struct {
		name   string
		substr string
		sev    Severity
	}{
		{"host_info_leak", "host:", SeverityMedium},
		{"kernel_leak", "Linux version", SeverityHigh},
		{"root_access", "root:x:0:0", SeverityCritical},
		{"docker_socket", "docker.sock", SeverityCritical},
		{"containerd_socket", "containerd.sock", SeverityCritical},
	}

	for _, p := range outputPatterns {
		if strings.Contains(output, p.substr) {
			detections = append(detections, Detection{
				Pattern:  p.name,
				Severity: p.sev.String(),
				Detail:   "suspicious content in output: " + p.name,
			})
		}
	}

	return detections
}

func defaultPatterns() []DetectionPattern {
	return []DetectionPattern{
		{
			Name:        "proc_self_access",
			Description: "Accessing /proc/self for process info",
			Regex:       regexp.MustCompile(`/proc/self/(root|exe|fd|ns|maps|status)`),
			Severity:    SeverityHigh,
		},
		{
			Name:        "container_breakout",
			Description: "Attempting container breakout via cgroup",
			Regex:       regexp.MustCompile(`/sys/fs/cgroup|notify_on_release|release_agent`),
			Severity:    SeverityCritical,
		},
		{
			Name:        "host_mount_access",
			Description: "Attempting to access host mounts",
			Regex:       regexp.MustCompile(`/var/run/docker|/var/run/containerd`),
			Severity:    SeverityCritical,
		},
		{
			Name:        "kernel_exploit",
			Description: "Potential kernel exploitation attempt",
			Regex:       regexp.MustCompile(`(?i)(dirty.?cow|dirty.?pipe|over(lay|l)fs|userfaultfd)`),
			Severity:    SeverityCritical,
		},
		{
			Name:        "metadata_service",
			Description: "Attempting to reach cloud metadata service",
			Regex:       regexp.MustCompile(`169\.254\.169\.254|metadata\.google|metadata\.aws`),
			Severity:    SeverityHigh,
		},
		{
			Name:        "reverse_shell",
			Description: "Potential reverse shell command",
			Regex:       regexp.MustCompile(`(?i)(nc|ncat|netcat|socat)\s+.*-[elp]|/dev/tcp/|bash\s+-i\s+>&`),
			Severity:    SeverityCritical,
		},
		{
			Name:        "capability_abuse",
			Description: "Attempting to manipulate capabilities",
			Regex:       regexp.MustCompile(`(?i)(cap_sys_admin|cap_net_raw|setcap|getcap|capsh)`),
			Severity:    SeverityHigh,
		},
		{
			Name:        "ptrace_attempt",
			Description: "Attempting to use ptrace for debugging/injection",
			Regex:       regexp.MustCompile(`(?i)(ptrace|process_vm_readv|process_vm_writev|PTRACE_ATTACH)`),
			Severity:    SeverityCritical,
		},
		{
			Name:        "symlink_race",
			Description: "Potential symlink race attack",
			Regex:       regexp.MustCompile(`ln\s+-sf?\s+/proc|ln\s+-sf?\s+/sys|ln\s+-sf?\s+/dev`),
			Severity:    SeverityHigh,
		},
		{
			Name:        "crypto_miner",
			Description: "Potential cryptocurrency mining",
			Regex:       regexp.MustCompile(`(?i)(stratum\+tcp|xmrig|minerd|cryptonight|hashrate)`),
			Severity:    SeverityMedium,
		},
	}
}
