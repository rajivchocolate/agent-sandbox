package sandbox

import (
	"fmt"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type ResourceLimits struct {
	CPUShares int64 `json:"cpu_shares"` // 1024 = 1 CPU core
	MemoryMB  int64 `json:"memory_mb"`  // Hard memory limit
	PidsLimit int64 `json:"pids_limit"` // Max processes (fork bomb protection)
	DiskMB    int64 `json:"disk_mb"`    // Tmpfs size for /tmp and /workspace
}

func DefaultLimits() ResourceLimits {
	return ResourceLimits{
		CPUShares: 512,  // 0.5 CPU
		MemoryMB:  256,  // 256MB
		PidsLimit: 50,   // 50 processes
		DiskMB:    100,  // 100MB tmpfs
	}
}

func (rl ResourceLimits) Validate() error {
	if rl.CPUShares < 2 || rl.CPUShares > 4096 {
		return fmt.Errorf("%w: cpu_shares must be 2-4096, got %d", ErrInvalidRequest, rl.CPUShares)
	}
	if rl.MemoryMB < 16 || rl.MemoryMB > 2048 {
		return fmt.Errorf("%w: memory_mb must be 16-2048, got %d", ErrInvalidRequest, rl.MemoryMB)
	}
	if rl.PidsLimit < 5 || rl.PidsLimit > 500 {
		return fmt.Errorf("%w: pids_limit must be 5-500, got %d", ErrInvalidRequest, rl.PidsLimit)
	}
	if rl.DiskMB < 1 || rl.DiskMB > 1024 {
		return fmt.Errorf("%w: disk_mb must be 1-1024, got %d", ErrInvalidRequest, rl.DiskMB)
	}
	return nil
}

func ApplyResourceLimits(spec *specs.Spec, limits ResourceLimits) {
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	if spec.Linux.Resources == nil {
		spec.Linux.Resources = &specs.LinuxResources{}
	}

	// Use CFS quota for a hard CPU cap instead of shares (soft, best-effort).
	// period=100ms, quota = (CPUShares/1024) * period.
	period := uint64(100000) // 100ms in microseconds
	quota := int64(float64(limits.CPUShares) / 1024.0 * float64(period))
	if quota < 1000 {
		quota = 1000 // minimum 1ms
	}

	spec.Linux.Resources.CPU = &specs.LinuxCPU{
		Period: &period,
		Quota:  &quota,
	}

	memoryBytes := limits.MemoryMB * 1024 * 1024
	spec.Linux.Resources.Memory = &specs.LinuxMemory{
		Limit: &memoryBytes,
		Swap:  &memoryBytes,
	}

	spec.Linux.Resources.Pids = &specs.LinuxPids{
		Limit: limits.PidsLimit,
	}

	tmpfsBytes := limits.DiskMB * 1024 * 1024
	spec.Mounts = appendIfNotExists(spec.Mounts, specs.Mount{
		Destination: "/tmp",
		Type:        "tmpfs",
		Source:      "tmpfs",
		Options: []string{
			"nosuid", "nodev",
			fmt.Sprintf("size=%d", tmpfsBytes),
			"mode=1777",
		},
	})

	spec.Process.Rlimits = []specs.POSIXRlimit{
		{Type: "RLIMIT_NOFILE", Hard: 256, Soft: 256},
		{Type: "RLIMIT_NPROC", Hard: safeUint64(limits.PidsLimit), Soft: safeUint64(limits.PidsLimit)},
		{Type: "RLIMIT_FSIZE", Hard: safeUint64(tmpfsBytes), Soft: safeUint64(tmpfsBytes)},
		{Type: "RLIMIT_CORE", Hard: 0, Soft: 0},
		{Type: "RLIMIT_STACK", Hard: 8388608, Soft: 8388608},
	}
}

func safeUint64(v int64) uint64 {
	if v < 0 {
		return 0
	}
	return uint64(v)
}

func appendIfNotExists(mounts []specs.Mount, m specs.Mount) []specs.Mount {
	for _, existing := range mounts {
		if existing.Destination == m.Destination {
			return mounts
		}
	}
	return append(mounts, m)
}
