package seccomp

import (
	"encoding/json"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func baseSyscalls(b *ProfileBuilder) *ProfileBuilder {
	return b.
		AllowSyscalls(
			"read", "write", "readv", "writev", "pread64", "pwrite64",
			"open", "openat", "close", "lseek",
			"stat", "fstat", "lstat", "newfstatat",
			"access", "faccessat", "faccessat2",
			"dup", "dup2", "dup3",
			"fcntl",
			"poll", "ppoll", "select", "pselect6",
			"pipe", "pipe2",
			"readlink", "readlinkat",
			"getdents64",
		).
		AllowSyscalls(
			"brk", "mmap", "munmap", "mprotect", "mremap",
			"madvise",
		).
		AllowSyscalls(
			"execve", "execveat",
			"exit", "exit_group",
			"wait4", "waitid",
			"clone", "clone3",
			"vfork",
			"set_tid_address",
			"set_robust_list", "get_robust_list",
		).
		AllowSyscalls(
			"futex",
			"gettid",
			"tgkill",
			"rt_sigaction", "rt_sigprocmask", "rt_sigreturn",
			"sigaltstack",
		).
		AllowSyscalls(
			"clock_gettime", "clock_getres",
			"gettimeofday",
			"nanosleep", "clock_nanosleep",
		).
		AllowSyscalls(
			"getpid", "getppid",
			"getuid", "geteuid",
			"getgid", "getegid",
			"uname",
			"getcwd",
		).
		AllowSyscalls(
			"epoll_create1", "epoll_ctl", "epoll_wait", "epoll_pwait",
			"eventfd2",
		).
		AllowSyscalls(
			"getrandom",
			"arch_prctl",
			"ioctl",
			"sysinfo",
			"getrlimit", "prlimit64",
			"umask",
			"chmod", "fchmod", "fchmodat",
			"chdir", "fchdir",
			"rename", "renameat", "renameat2",
			"unlink", "unlinkat",
			"mkdir", "mkdirat",
			"rmdir",
			"symlink", "symlinkat",
			"link", "linkat",
			"ftruncate",
			"fallocate",
			"fsync", "fdatasync",
			"flock",
			"statfs", "fstatfs",
			"statx",
			"copy_file_range",
		).
		// prctl restricted to PR_SET_NAME (15) and PR_GET_NAME (16) only
		AllowSyscallWithArgs("prctl", []SyscallArg{
			{Index: 0, Value: 15, Op: specs.OpEqualTo}, // PR_SET_NAME
		}).
		AllowSyscallWithArgs("prctl", []SyscallArg{
			{Index: 0, Value: 16, Op: specs.OpEqualTo}, // PR_GET_NAME
		})
}

func dangerousSyscalls(b *ProfileBuilder) *ProfileBuilder {
	return b.
		TrapSyscalls(
			"ptrace",
			"process_vm_readv", "process_vm_writev",
			"keyctl",
			"add_key", "request_key",
			"bpf",
			"perf_event_open",
			"userfaultfd",
			"memfd_create", // fileless execution: anonymous in-memory files executable via /proc/self/fd
			"kexec_load", "kexec_file_load",
			"finit_module", "init_module", "delete_module",
		).
		BlockSyscalls(
			"mount", "umount2", "pivot_root",
			"reboot",
			"swapon", "swapoff",
			"sethostname", "setdomainname",
			"setns", "unshare",
			"acct",
			"settimeofday", "adjtimex", "clock_adjtime",
			"nfsservctl",
			"personality",
			"lookup_dcookie",
			"ioperm", "iopl",
		)
}

// DefaultProfile returns a deny-by-default seccomp profile with allowlisted
// syscalls for Python, Node.js, and Bash.
func DefaultProfile() *specs.LinuxSeccomp {
	b := NewBuilder()
	b = baseSyscalls(b)
	b = dangerousSyscalls(b)
	return b.Build()
}

// dockerSeccompProfile mirrors the Docker daemon's seccomp profile JSON format.
type dockerSeccompProfile struct {
	DefaultAction string               `json:"defaultAction"`
	Architectures []string             `json:"architectures"`
	Syscalls      []dockerSeccompRule   `json:"syscalls"`
}

type dockerSeccompRule struct {
	Names  []string              `json:"names"`
	Action string                `json:"action"`
	Args   []dockerSeccompArg    `json:"args,omitempty"`
}

type dockerSeccompArg struct {
	Index    uint   `json:"index"`
	Value    uint64 `json:"value"`
	Op       string `json:"op"`
}

// DockerProfileJSON exports the default seccomp allowlist as Docker-format JSON
// suitable for --security-opt seccomp=<path>.
func DockerProfileJSON() ([]byte, error) {
	return profileToDockerJSON(DefaultProfile())
}

// DockerNetworkProfileJSON exports the network-enabled seccomp allowlist as Docker-format JSON.
func DockerNetworkProfileJSON() ([]byte, error) {
	return profileToDockerJSON(NetworkAllowProfile())
}

func profileToDockerJSON(profile *specs.LinuxSeccomp) ([]byte, error) {
	actionMap := map[specs.LinuxSeccompAction]string{
		specs.ActAllow: "SCMP_ACT_ALLOW",
		specs.ActErrno: "SCMP_ACT_ERRNO",
		specs.ActTrap:  "SCMP_ACT_TRAP",
		specs.ActLog:   "SCMP_ACT_LOG",
		specs.ActKill:  "SCMP_ACT_KILL",
	}
	archMap := map[specs.Arch]string{
		specs.ArchX86_64:  "SCMP_ARCH_X86_64",
		specs.ArchAARCH64: "SCMP_ARCH_AARCH64",
		specs.ArchX86:     "SCMP_ARCH_X86",
		specs.ArchARM:     "SCMP_ARCH_ARM",
	}
	opMap := map[specs.LinuxSeccompOperator]string{
		specs.OpEqualTo:      "SCMP_CMP_EQ",
		specs.OpNotEqual:     "SCMP_CMP_NE",
		specs.OpGreaterThan:  "SCMP_CMP_GT",
		specs.OpGreaterEqual: "SCMP_CMP_GE",
		specs.OpLessThan:     "SCMP_CMP_LT",
		specs.OpLessEqual:    "SCMP_CMP_LE",
		specs.OpMaskedEqual:  "SCMP_CMP_MASKED_EQ",
	}

	dp := dockerSeccompProfile{
		DefaultAction: actionMap[profile.DefaultAction],
	}
	for _, a := range profile.Architectures {
		if s, ok := archMap[a]; ok {
			dp.Architectures = append(dp.Architectures, s)
		}
	}
	for _, sc := range profile.Syscalls {
		rule := dockerSeccompRule{
			Names:  sc.Names,
			Action: actionMap[sc.Action],
		}
		for _, arg := range sc.Args {
			rule.Args = append(rule.Args, dockerSeccompArg{
				Index: arg.Index,
				Value: arg.Value,
				Op:    opMap[arg.Op],
			})
		}
		dp.Syscalls = append(dp.Syscalls, rule)
	}
	return json.Marshal(dp)
}

// NetworkAllowProfile adds socket/connect/bind to the default profile.
func NetworkAllowProfile() *specs.LinuxSeccomp {
	b := NewBuilder()
	b = baseSyscalls(b)

	// Network syscalls
	b.AllowSyscalls(
		"socket", "connect", "bind", "listen", "accept", "accept4",
		"sendto", "recvfrom", "sendmsg", "recvmsg",
		"getsockopt", "setsockopt",
		"getsockname", "getpeername",
		"shutdown",
	)

	b = dangerousSyscalls(b)
	return b.Build()
}
