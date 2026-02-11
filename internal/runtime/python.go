package runtime

import (
	"fmt"
	"strings"
)

// PythonRuntime configures execution of Python code.
type PythonRuntime struct{}

func (p *PythonRuntime) Name() string { return "python" }

func (p *PythonRuntime) Image() string { return "docker.io/library/python:3.12-slim" }

func (p *PythonRuntime) Command(codePath string) []string {
	return []string{
		"python3", "-u", // Unbuffered output
		"-B",            // Don't write .pyc files
		codePath,
	}
}

func (p *PythonRuntime) FileExtension() string { return ".py" }

func (p *PythonRuntime) Validate(code string) error {
	if len(code) == 0 {
		return fmt.Errorf("empty code")
	}
	if len(code) > 1<<20 { // 1MB limit
		return fmt.Errorf("code too large: %d bytes (max 1MB)", len(code))
	}

	// Best-effort check for obviously dangerous patterns.
	// The sandbox enforces real security; this is just early feedback.
	dangerous := []string{
		"__import__('os').system",
		"subprocess.call",
		"ctypes.CDLL",
	}
	lower := strings.ToLower(code)
	for _, pattern := range dangerous {
		if strings.Contains(lower, strings.ToLower(pattern)) {
			// Don't block, just note it — the sandbox will enforce real limits
			break
		}
	}

	return nil
}
