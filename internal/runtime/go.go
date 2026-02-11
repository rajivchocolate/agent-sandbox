package runtime

import "fmt"

// GoRuntime configures execution of Go code.
type GoRuntime struct{}

func (g *GoRuntime) Name() string { return "go" }

func (g *GoRuntime) Image() string { return "docker.io/library/golang:1.24-alpine" }

func (g *GoRuntime) Command(codePath string) []string {
	return []string{"go", "run", codePath}
}

func (g *GoRuntime) FileExtension() string { return ".go" }

func (g *GoRuntime) Validate(code string) error {
	if len(code) == 0 {
		return fmt.Errorf("empty code")
	}
	if len(code) > 1<<20 {
		return fmt.Errorf("code too large: %d bytes (max 1MB)", len(code))
	}
	return nil
}
