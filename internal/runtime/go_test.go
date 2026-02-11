package runtime

import (
	"strings"
	"testing"
)

func TestGoRuntime_Name(t *testing.T) {
	g := &GoRuntime{}
	if g.Name() != "go" {
		t.Errorf("Name() = %q, want %q", g.Name(), "go")
	}
}

func TestGoRuntime_Image(t *testing.T) {
	g := &GoRuntime{}
	if g.Image() != "docker.io/library/golang:1.24-alpine" {
		t.Errorf("Image() = %q, want %q", g.Image(), "docker.io/library/golang:1.24-alpine")
	}
}

func TestGoRuntime_Command(t *testing.T) {
	g := &GoRuntime{}
	cmd := g.Command("/workspace/code.go")
	if len(cmd) != 3 {
		t.Fatalf("Command() len = %d, want 3", len(cmd))
	}
	if cmd[0] != "go" || cmd[1] != "run" || cmd[2] != "/workspace/code.go" {
		t.Errorf("Command() = %v, want [go run /workspace/code.go]", cmd)
	}
}

func TestGoRuntime_FileExtension(t *testing.T) {
	g := &GoRuntime{}
	if g.FileExtension() != ".go" {
		t.Errorf("FileExtension() = %q, want %q", g.FileExtension(), ".go")
	}
}

func TestGoRuntime_Validate(t *testing.T) {
	g := &GoRuntime{}

	if err := g.Validate("package main"); err != nil {
		t.Errorf("Validate(valid code) = %v, want nil", err)
	}
	if err := g.Validate(""); err == nil {
		t.Error("Validate(empty) should return error")
	}
	if err := g.Validate(strings.Repeat("x", 1<<20+1)); err == nil {
		t.Error("Validate(>1MB) should return error")
	}
}

func TestGoRuntime_RegisteredInRegistry(t *testing.T) {
	r := NewRegistry()
	rt, err := r.Get("go")
	if err != nil {
		t.Fatalf("Get(go) = %v", err)
	}
	if rt.Name() != "go" {
		t.Errorf("registered runtime name = %q, want %q", rt.Name(), "go")
	}
}
