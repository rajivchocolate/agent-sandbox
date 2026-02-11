package runtime

import "fmt"

// NodeRuntime configures execution of Node.js code.
type NodeRuntime struct{}

func (n *NodeRuntime) Name() string { return "node" }

func (n *NodeRuntime) Image() string { return "docker.io/library/node:20-slim" }

func (n *NodeRuntime) Command(codePath string) []string {
	return []string{
		"node",
		"--max-old-space-size=256", // Limit V8 heap
		"--disallow-code-generation-from-strings", // Block eval()
		codePath,
	}
}

func (n *NodeRuntime) FileExtension() string { return ".js" }

func (n *NodeRuntime) Validate(code string) error {
	if len(code) == 0 {
		return fmt.Errorf("empty code")
	}
	if len(code) > 1<<20 {
		return fmt.Errorf("code too large: %d bytes (max 1MB)", len(code))
	}
	return nil
}
