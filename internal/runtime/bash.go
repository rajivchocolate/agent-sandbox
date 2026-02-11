package runtime

import "fmt"

// BashRuntime configures execution of Bash scripts.
type BashRuntime struct{}

func (b *BashRuntime) Name() string { return "bash" }

func (b *BashRuntime) Image() string { return "docker.io/library/alpine:3.19" }

func (b *BashRuntime) Command(codePath string) []string {
	return []string{
		"/bin/sh",
		"-e",  // Exit on error
		"-u",  // Treat unset variables as error
		codePath,
	}
}

func (b *BashRuntime) FileExtension() string { return ".sh" }

func (b *BashRuntime) Validate(code string) error {
	if len(code) == 0 {
		return fmt.Errorf("empty code")
	}
	if len(code) > 1<<20 {
		return fmt.Errorf("code too large: %d bytes (max 1MB)", len(code))
	}
	return nil
}
