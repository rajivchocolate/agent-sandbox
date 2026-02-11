package runtime

import "fmt"

type ClaudeRuntime struct{}

func (c *ClaudeRuntime) Name() string { return "claude" }

func (c *ClaudeRuntime) Image() string { return "sandbox-claude:latest" }

func (c *ClaudeRuntime) Command(codePath string) []string {
	// Use positional params ($1) instead of string interpolation for defense in depth.
	// codePath is our temp file so low risk, but this prevents any shell metacharacter issues.
	return []string{
		"sh", "-c",
		`cat "$1" | claude -p --dangerously-skip-permissions --output-format text`,
		"_", codePath,
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
