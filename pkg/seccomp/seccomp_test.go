package seccomp

import (
	"encoding/json"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestDefaultProfile_DenyByDefault(t *testing.T) {
	p := DefaultProfile()
	if p.DefaultAction != specs.ActErrno {
		t.Errorf("DefaultAction = %v, want ActErrno", p.DefaultAction)
	}
}

func TestDefaultProfile_MemfdCreateAllowed(t *testing.T) {
	p := DefaultProfile()
	found := false
	for _, rule := range p.Syscalls {
		if rule.Action == specs.ActAllow {
			for _, name := range rule.Names {
				if name == "memfd_create" {
					found = true
					break
				}
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Error("memfd_create should be allowed in default profile")
	}
}

func TestNetworkProfile_HasSocketSyscalls(t *testing.T) {
	p := NetworkAllowProfile()

	needed := map[string]bool{"socket": false, "connect": false, "bind": false}
	for _, rule := range p.Syscalls {
		if rule.Action == specs.ActAllow {
			for _, name := range rule.Names {
				if _, ok := needed[name]; ok {
					needed[name] = true
				}
			}
		}
	}
	for name, found := range needed {
		if !found {
			t.Errorf("network profile missing allowed syscall %q", name)
		}
	}
}

func TestDefaultProfile_NoNetworkSyscalls(t *testing.T) {
	p := DefaultProfile()
	for _, rule := range p.Syscalls {
		if rule.Action == specs.ActAllow {
			for _, name := range rule.Names {
				if name == "socket" {
					t.Error("default (no-network) profile should not allow 'socket'")
					return
				}
			}
		}
	}
}

func TestDockerProfileJSON_ValidJSON(t *testing.T) {
	data, err := DockerProfileJSON()
	if err != nil {
		t.Fatalf("DockerProfileJSON: %v", err)
	}

	var dp struct {
		DefaultAction string `json:"defaultAction"`
		Syscalls      []struct {
			Names  []string `json:"names"`
			Action string   `json:"action"`
		} `json:"syscalls"`
	}
	if err := json.Unmarshal(data, &dp); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if dp.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("defaultAction = %q, want SCMP_ACT_ERRNO", dp.DefaultAction)
	}
	if len(dp.Syscalls) == 0 {
		t.Error("expected syscall rules, got none")
	}
}

func TestProfileBuilder(t *testing.T) {
	p := NewBuilder().AllowSyscalls("read", "write").Build()

	if p.DefaultAction != specs.ActErrno {
		t.Errorf("DefaultAction = %v, want ActErrno", p.DefaultAction)
	}
	if len(p.Syscalls) != 1 {
		t.Fatalf("got %d rules, want 1", len(p.Syscalls))
	}
	rule := p.Syscalls[0]
	if rule.Action != specs.ActAllow {
		t.Errorf("rule Action = %v, want ActAllow", rule.Action)
	}
	if len(rule.Names) != 2 {
		t.Errorf("got %d names, want 2", len(rule.Names))
	}
	if rule.Names[0] != "read" || rule.Names[1] != "write" {
		t.Errorf("names = %v, want [read write]", rule.Names)
	}
}
