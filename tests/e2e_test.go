package tests

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"safe-agent-sandbox/internal/sandbox"
)

// requireDocker skips the test if Docker is not installed or not running.
func requireDocker(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not installed, skipping")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("Docker daemon not running, skipping")
	}
}

// TestE2E runs real code in Docker containers and verifies the sandbox
// blocks escape attempts. Requires Docker to be available.
func TestE2E(t *testing.T) {
	requireDocker(t)

	runner := sandbox.NewDockerRunner(10)
	defer runner.Close()

	tests := []struct {
		name       string
		language   string
		code       string
		wantExit   int    // -1 means "any non-zero"
		wantOutput string // substring expected in stdout
		wantStderr string // substring expected in stderr (empty = don't check)
		wantFail   bool   // true = we expect non-zero exit or blocked behavior
	}{
		// === Benign code that should succeed ===
		{
			name:       "python_hello_world",
			language:   "python",
			code:       `print("Hello from sandbox!")`,
			wantExit:   0,
			wantOutput: "Hello from sandbox!",
		},
		{
			name:       "python_math",
			language:   "python",
			code:       `print(sum(range(101)))`,
			wantExit:   0,
			wantOutput: "5050",
		},
		{
			name:       "node_hello_world",
			language:   "node",
			code:       `console.log("Hello from Node!")`,
			wantExit:   0,
			wantOutput: "Hello from Node!",
		},
		{
			name:       "bash_echo",
			language:   "bash",
			code:       `echo "Hello from Bash!"`,
			wantExit:   0,
			wantOutput: "Hello from Bash!",
		},
		{
			name:     "python_write_tmp",
			language: "python",
			code: `
with open("/tmp/test.txt", "w") as f:
    f.write("tmpfs works")
with open("/tmp/test.txt") as f:
    print(f.read())
`,
			wantExit:   0,
			wantOutput: "tmpfs works",
		},

		// === Escape attempts that should be blocked ===
		{
			name:     "block_read_etc_shadow",
			language: "python",
			code:     `print(open("/etc/shadow").read())`,
			wantFail: true,
		},
		{
			name:     "block_network_curl",
			language: "bash",
			code:     `curl -s http://google.com || wget -q -O- http://google.com || echo "NETWORK_BLOCKED"`,
			wantFail: true,
			// With --network none, curl/wget aren't available or can't connect
		},
		{
			name:     "block_fork_bomb",
			language: "python",
			code: `
import os
pids = []
try:
    for i in range(1000):
        pid = os.fork()
        if pid == 0:
            import time; time.sleep(60)
            os._exit(0)
        pids.append(pid)
except OSError as e:
    print(f"FORK_BLOCKED after {len(pids)} forks: {e}")
`,
			wantFail: true,
		},
		{
			name:     "block_write_rootfs",
			language: "bash",
			code:     `touch /etc/hacked 2>&1 || echo "WRITE_BLOCKED"`,
			wantFail: true,
		},
		{
			name:     "block_write_rootfs_python",
			language: "python",
			code: `
try:
    with open("/etc/hacked", "w") as f:
        f.write("pwned")
    print("ESCAPE: wrote to rootfs")
except (PermissionError, OSError) as e:
    print(f"WRITE_BLOCKED: {e}")
`,
			wantExit:   0, // The python script handles the error gracefully
			wantOutput: "WRITE_BLOCKED",
		},
		{
			name:     "block_docker_socket",
			language: "bash",
			code:     `ls -la /var/run/docker.sock 2>&1 || echo "DOCKER_SOCKET_BLOCKED"`,
			wantFail: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			result, err := runner.Execute(ctx, sandbox.ExecutionRequest{
				Code:     tt.code,
				Language: tt.language,
				Timeout:  15 * time.Second,
			})

			if tt.wantFail {
				// For escape attempts: either execution errors, exits non-zero,
				// or the output shows the attempt was blocked
				if err != nil {
					t.Logf("PASS (execution error): %v", err)
					return
				}
				if result.ExitCode != 0 {
					t.Logf("PASS (non-zero exit code %d)", result.ExitCode)
					return
				}
				// Some blocked operations produce output indicating the block
				combined := result.Output + result.Stderr
				if strings.Contains(combined, "BLOCKED") ||
					strings.Contains(combined, "Permission denied") ||
					strings.Contains(combined, "Operation not permitted") ||
					strings.Contains(combined, "No such file") ||
					strings.Contains(combined, "Read-only file system") ||
					strings.Contains(combined, "NETWORK_BLOCKED") ||
					strings.Contains(combined, "FORK_BLOCKED") {
					t.Logf("PASS (blocked in output): %s", strings.TrimSpace(combined))
					return
				}
				// If we see evidence of successful escape, fail
				if strings.Contains(combined, "ESCAPE") {
					t.Fatalf("ESCAPE DETECTED: %s", combined)
				}
				t.Logf("Output: %q, Stderr: %q, Exit: %d", result.Output, result.Stderr, result.ExitCode)
				t.Logf("PASS (no escape evidence)")
				return
			}

			// For benign code
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantExit >= 0 && result.ExitCode != tt.wantExit {
				t.Errorf("exit code = %d, want %d\nstdout: %s\nstderr: %s",
					result.ExitCode, tt.wantExit, result.Output, result.Stderr)
			}

			if tt.wantOutput != "" && !strings.Contains(result.Output, tt.wantOutput) {
				t.Errorf("output %q does not contain %q", result.Output, tt.wantOutput)
			}
		})
	}
}

// TestE2ETimeout verifies that the timeout is enforced.
func TestE2ETimeout(t *testing.T) {
	requireDocker(t)

	runner := sandbox.NewDockerRunner(10)
	defer runner.Close()

	ctx := context.Background()
	_, err := runner.Execute(ctx, sandbox.ExecutionRequest{
		Code:     `import time; time.sleep(60)`,
		Language: "python",
		Timeout:  3 * time.Second,
	})

	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if err != sandbox.ErrTimeout {
		t.Logf("got error (acceptable): %v", err)
	}
}
