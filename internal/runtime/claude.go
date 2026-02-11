package runtime

import "fmt"

type ClaudeRuntime struct{}

func (c *ClaudeRuntime) Name() string { return "claude" }

func (c *ClaudeRuntime) Image() string { return "sandbox-claude:latest" }

func (c *ClaudeRuntime) Command(codePath string) []string {
	// Pipe the prompt file into claude via stdin to avoid shell injection.
	// Single-quoted path prevents any shell metacharacter expansion.
	return []string{
		"sh", "-c",
		fmt.Sprintf("cat '%s' | claude -p --dangerously-skip-permissions --output-format text", codePath),
	}
}

func (c *ClaudeRuntime) FileExtension() string { return ".txt" }

func (c *ClaudeRuntime) Validate(code string) error {
	if len(code) == 0 {
		return fmt.Errorf("empty prompt")
	}
	if len(code) > 1<<20 {
		return fmt.Errorf("prompt too large: %d bytes (max 1MB)", len(code))
	}
	return nil
}
