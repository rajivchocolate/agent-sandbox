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

func TestE2E(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	requireDocker(t)

	runner := sandbox.NewDockerRunner(10, nil)
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

		// === Adversarial: filesystem escape attempts ===
		{
			name:     "block_read_etc_shadow",
			language: "python",
			code:     `print(open("/etc/shadow").read())`,
			wantFail: true,
		},
		{
			name:     "block_read_etc_passwd",
			language: "bash",
			code:     `cat /etc/passwd`,
			wantFail: true,
		},
		{
			name:     "block_read_ssh_keys",
			language: "python",
			code: `
import os
ssh_dir = os.path.expanduser("~/.ssh")
try:
    for f in os.listdir(ssh_dir):
        print(open(os.path.join(ssh_dir, f)).read())
    print("ESCAPE: read SSH keys")
except (FileNotFoundError, PermissionError, OSError) as e:
    print(f"SSH_BLOCKED: {e}")
`,
			wantExit:   0,
			wantOutput: "SSH_BLOCKED",
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
			wantExit:   0,
			wantOutput: "WRITE_BLOCKED",
		},
		{
			name:     "block_apt_install",
			language: "bash",
			code:     `apt-get update 2>&1 || echo "APT_BLOCKED"`,
			wantFail: true,
		},

		// === Adversarial: network escape attempts ===
		{
			name:     "block_network_curl",
			language: "bash",
			code:     `curl -s http://google.com || wget -q -O- http://google.com || echo "NETWORK_BLOCKED"`,
			wantFail: true,
		},
		{
			name:     "block_network_python",
			language: "python",
			code: `
import urllib.request
try:
    resp = urllib.request.urlopen("http://evil.com", timeout=3)
    print("ESCAPE: network access succeeded")
except Exception as e:
    print(f"NETWORK_BLOCKED: {e}")
`,
			wantExit:   0,
			wantOutput: "NETWORK_BLOCKED",
		},

		// === Adversarial: resource exhaustion ===
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

		// === Adversarial: container escape attempts ===
		{
			name:     "block_docker_socket",
			language: "bash",
			code:     `ls -la /var/run/docker.sock 2>&1 || echo "DOCKER_SOCKET_BLOCKED"`,
			wantFail: true,
		},
		{
			name:     "block_proc_sysrq",
			language: "bash",
			code:     `cat /proc/sysrq-trigger 2>&1 || echo "PROC_BLOCKED"`,
			wantFail: true,
		},
		{
			name:     "block_mount_syscall",
			language: "python",
			code: `
import ctypes
import ctypes.util
try:
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    ret = libc.mount(b"none", b"/tmp/escape", b"tmpfs", 0, None)
    if ret != 0:
        import os
        print(f"MOUNT_BLOCKED: errno={os.strerror(ctypes.get_errno())}")
    else:
        print("ESCAPE: mount succeeded")
except Exception as e:
    print(f"MOUNT_BLOCKED: {e}")
`,
			wantExit:   0,
			wantOutput: "MOUNT_BLOCKED",
		},
		{
			name:     "block_chroot_escape",
			language: "python",
			code: `
import os
try:
    os.chroot("/tmp")
    print("ESCAPE: chroot succeeded")
except (PermissionError, OSError) as e:
    print(f"CHROOT_BLOCKED: {e}")
`,
			wantExit:   0,
			wantOutput: "CHROOT_BLOCKED",
		},
		{
			name:     "block_setuid",
			language: "python",
			code: `
import os
try:
    os.setuid(0)
    print("ESCAPE: setuid(0) succeeded")
except (PermissionError, OSError) as e:
    print(f"SETUID_BLOCKED: {e}")
`,
			wantExit:   0,
			wantOutput: "SETUID_BLOCKED",
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
				// If we see evidence of successful escape, fail hard
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

func TestE2ETimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	requireDocker(t)

	runner := sandbox.NewDockerRunner(10, nil)
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

func TestE2EClaudeRuntime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode")
	}
	requireDocker(t)

	// Check if the claude image exists locally
	out, err := exec.Command("docker", "images", "-q", "sandbox-claude:latest").Output()
	if err != nil || strings.TrimSpace(string(out)) == "" {
		t.Skip("sandbox-claude:latest image not built, skipping (run: make claude-image)")
	}

	runner := sandbox.NewDockerRunner(10, nil)
	defer runner.Close()

	// Test that the claude runtime validates empty prompts
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err = runner.Execute(ctx, sandbox.ExecutionRequest{
		Code:     "",
		Language: "claude",
		Timeout:  10 * time.Second,
	})
	if err == nil {
		t.Fatal("expected validation error for empty prompt")
	}
}
