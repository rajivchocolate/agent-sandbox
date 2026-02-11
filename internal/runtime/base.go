package runtime

import (
	"fmt"
)

// Runtime defines how to execute code for a specific language.
type Runtime interface {
	// Name returns the runtime identifier (e.g., "python", "node", "bash").
	Name() string

	// Image returns the container image reference for this runtime.
	Image() string

	// Command returns the command and args to execute the given code.
	// The code will be written to codePath inside the container.
	Command(codePath string) []string

	// FileExtension returns the file extension for code files (e.g., ".py").
	FileExtension() string

	// Validate checks if the code is syntactically acceptable before execution.
	// This is a best-effort pre-check, not a full parser.
	Validate(code string) error
}

// Registry maps language names to their Runtime implementations.
type Registry struct {
	runtimes map[string]Runtime
}

// NewRegistry creates a registry with all supported runtimes.
func NewRegistry() *Registry {
	r := &Registry{
		runtimes: make(map[string]Runtime),
	}
	r.Register(&PythonRuntime{})
	r.Register(&NodeRuntime{})
	r.Register(&BashRuntime{})
	return r
}

// Register adds a runtime to the registry.
func (r *Registry) Register(rt Runtime) {
	r.runtimes[rt.Name()] = rt
}

// Get returns the runtime for the given language.
func (r *Registry) Get(language string) (Runtime, error) {
	rt, ok := r.runtimes[language]
	if !ok {
		return nil, fmt.Errorf("unsupported language: %q (supported: python, node, bash)", language)
	}
	return rt, nil
}

// Languages returns all registered language names.
func (r *Registry) Languages() []string {
	langs := make([]string, 0, len(r.runtimes))
	for name := range r.runtimes {
		langs = append(langs, name)
	}
	return langs
}

// Images returns all container images needed by registered runtimes.
func (r *Registry) Images() []string {
	images := make([]string, 0, len(r.runtimes))
	for _, rt := range r.runtimes {
		images = append(images, rt.Image())
	}
	return images
}
