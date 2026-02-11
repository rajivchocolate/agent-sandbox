package sandbox

import "testing"

func TestDevLimits(t *testing.T) {
	l := DevLimits()
	if l.CPUShares != 4096 {
		t.Errorf("CPUShares = %d, want 4096", l.CPUShares)
	}
	if l.MemoryMB != 4096 {
		t.Errorf("MemoryMB = %d, want 4096", l.MemoryMB)
	}
	if l.PidsLimit != 500 {
		t.Errorf("PidsLimit = %d, want 500", l.PidsLimit)
	}
	if l.DiskMB != 2048 {
		t.Errorf("DiskMB = %d, want 2048", l.DiskMB)
	}
}

func TestValidate_DevTierCeilings(t *testing.T) {
	// DevLimits should pass validation with the raised ceilings.
	if err := DevLimits().Validate(); err != nil {
		t.Errorf("DevLimits().Validate() = %v, want nil", err)
	}

	// Values at the new ceilings should pass.
	max := ResourceLimits{CPUShares: 8192, MemoryMB: 16384, PidsLimit: 2000, DiskMB: 10240}
	if err := max.Validate(); err != nil {
		t.Errorf("max ceilings Validate() = %v, want nil", err)
	}

	// Values above the new ceilings should fail.
	tests := []struct {
		name   string
		limits ResourceLimits
	}{
		{"cpu over", ResourceLimits{CPUShares: 8193, MemoryMB: 256, PidsLimit: 50, DiskMB: 100}},
		{"memory over", ResourceLimits{CPUShares: 512, MemoryMB: 16385, PidsLimit: 50, DiskMB: 100}},
		{"pids over", ResourceLimits{CPUShares: 512, MemoryMB: 256, PidsLimit: 2001, DiskMB: 100}},
		{"disk over", ResourceLimits{CPUShares: 512, MemoryMB: 256, PidsLimit: 50, DiskMB: 10241}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.limits.Validate(); err == nil {
				t.Error("expected validation error for over-ceiling value")
			}
		})
	}
}

func TestDefaultLimits(t *testing.T) {
	l := DefaultLimits()
	if l.CPUShares != 512 {
		t.Errorf("CPUShares = %d, want 512", l.CPUShares)
	}
	if l.MemoryMB != 256 {
		t.Errorf("MemoryMB = %d, want 256", l.MemoryMB)
	}
	if l.PidsLimit != 50 {
		t.Errorf("PidsLimit = %d, want 50", l.PidsLimit)
	}
	if l.DiskMB != 100 {
		t.Errorf("DiskMB = %d, want 100", l.DiskMB)
	}
}
