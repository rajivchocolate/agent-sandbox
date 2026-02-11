package seccomp

import (
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
			"prctl",
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
			"memfd_create",
			"copy_file_range",
		)
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
