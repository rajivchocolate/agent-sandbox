package sandbox

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"

	"safe-agent-sandbox/pkg/seccomp"
)

type SecurityProfile struct {
	Seccomp       *specs.LinuxSeccomp
	Capabilities  []string
	Namespaces    []specs.LinuxNamespace
	MaskedPaths   []string
	ReadonlyPaths []string
}

func DefaultSecurityProfile() SecurityProfile {
	return SecurityProfile{
		Seccomp:      seccomp.DefaultProfile(),
		Capabilities: []string{},
		Namespaces: []specs.LinuxNamespace{
			{Type: specs.PIDNamespace},
			{Type: specs.NetworkNamespace},
			{Type: specs.MountNamespace},
			{Type: specs.UTSNamespace},
			{Type: specs.IPCNamespace},
			{Type: specs.UserNamespace},
		},
		MaskedPaths: []string{
			"/proc/acpi",
			"/proc/kcore",
			"/proc/keys",
			"/proc/latency_stats",
			"/proc/timer_list",
			"/proc/timer_stats",
			"/proc/sched_debug",
			"/proc/scsi",
			"/sys/firmware",
			"/sys/devices/virtual/powercap",
		},
		ReadonlyPaths: []string{
			"/proc/asound",
			"/proc/bus",
			"/proc/fs",
			"/proc/irq",
			"/proc/sys",
			"/proc/sysrq-trigger",
		},
	}
}

// NetworkAllowedSecurityProfile is the same as default but allows network syscalls.
func NetworkAllowedSecurityProfile() SecurityProfile {
	profile := DefaultSecurityProfile()
	profile.Seccomp = seccomp.NetworkAllowProfile()
	return profile
}

func ApplySecurityProfile(spec *specs.Spec, profile SecurityProfile) {
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	if spec.Process == nil {
		spec.Process = &specs.Process{}
	}
	if spec.Process.Capabilities == nil {
		spec.Process.Capabilities = &specs.LinuxCapabilities{}
	}

	spec.Linux.Seccomp = profile.Seccomp
	spec.Process.Capabilities.Bounding = profile.Capabilities
	spec.Process.Capabilities.Effective = profile.Capabilities
	spec.Process.Capabilities.Inheritable = profile.Capabilities
	spec.Process.Capabilities.Permitted = profile.Capabilities
	spec.Process.Capabilities.Ambient = profile.Capabilities

	spec.Linux.Namespaces = profile.Namespaces
	spec.Linux.MaskedPaths = profile.MaskedPaths
	spec.Linux.ReadonlyPaths = profile.ReadonlyPaths

	spec.Process.NoNewPrivileges = true
	spec.Process.User = specs.User{
		UID: 65534,
		GID: 65534,
	}

	if spec.Root != nil {
		spec.Root.Readonly = true
	}
}
