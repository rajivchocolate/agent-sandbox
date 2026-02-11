package seccomp

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type ProfileBuilder struct {
	profile *specs.LinuxSeccomp
}

func NewBuilder() *ProfileBuilder {
	return &ProfileBuilder{
		profile: &specs.LinuxSeccomp{
			DefaultAction: specs.ActErrno,
			Architectures: []specs.Arch{
				specs.ArchX86_64,
				specs.ArchAARCH64,
			},
		},
	}
}

func (b *ProfileBuilder) AllowSyscalls(names ...string) *ProfileBuilder {
	b.profile.Syscalls = append(b.profile.Syscalls, specs.LinuxSyscall{
		Names:  names,
		Action: specs.ActAllow,
	})
	return b
}

func (b *ProfileBuilder) BlockSyscalls(names ...string) *ProfileBuilder {
	b.profile.Syscalls = append(b.profile.Syscalls, specs.LinuxSyscall{
		Names:  names,
		Action: specs.ActErrno,
	})
	return b
}

func (b *ProfileBuilder) LogSyscalls(names ...string) *ProfileBuilder {
	b.profile.Syscalls = append(b.profile.Syscalls, specs.LinuxSyscall{
		Names:  names,
		Action: specs.ActLog,
	})
	return b
}

func (b *ProfileBuilder) TrapSyscalls(names ...string) *ProfileBuilder {
	b.profile.Syscalls = append(b.profile.Syscalls, specs.LinuxSyscall{
		Names:  names,
		Action: specs.ActTrap,
	})
	return b
}

func (b *ProfileBuilder) WithArchitectures(archs ...specs.Arch) *ProfileBuilder {
	b.profile.Architectures = archs
	return b
}

func (b *ProfileBuilder) Build() *specs.LinuxSeccomp {
	return b.profile
}
