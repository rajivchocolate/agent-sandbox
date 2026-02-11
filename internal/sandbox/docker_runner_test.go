package sandbox

import (
	"strings"
	"testing"
	"time"

	"safe-agent-sandbox/internal/runtime"
)

// newTestRunner builds a DockerRunner suitable for unit tests.
// It bypasses NewDockerRunner to avoid Docker host resolution and the cleanup goroutine.
func newTestRunner(proxyPort int, proxySecret string, allowedRoots []string) *DockerRunner {
	return &DockerRunner{
		runtimes:     runtime.NewRegistry(),
		sem:          make(chan struct{}, 10),
		claudeSem:    make(chan struct{}, 5),
		proxyPort:    proxyPort,
		proxySecret:  proxySecret,
		allowedRoots: allowedRoots,
	}
}

// argsContain returns true if the args slice contains needle.
func argsContain(args []string, needle string) bool {
	for _, a := range args {
		if a == needle {
			return true
		}
	}
	return false
}

// argsContainPrefix returns true if any arg starts with the given prefix.
func argsContainPrefix(args []string, prefix string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func TestBuildDockerArgs_StandardRuntime(t *testing.T) {
	d := newTestRunner(0, "", nil)
	rt, _ := d.runtimes.Get("python")

	args := d.buildDockerArgs("exec-1", rt,
		"/tmp/code.py", "/workspace/code.py",
		"/tmp/sandbox-exec-1", "/tmp/seccomp.json",
		ExecutionRequest{Language: "python", Code: "print(1)"},
	)

	if !argsContain(args, "none") {
		t.Error("expected --network none for standard runtime")
	}
	if !argsContain(args, "--read-only") {
		t.Error("expected --read-only for non-claude runtime")
	}
	if !argsContain(args, "65534:65534") {
		t.Error("expected --user 65534:65534")
	}
	if argsContainPrefix(args, "ANTHROPIC_BASE_URL") {
		t.Error("ANTHROPIC_BASE_URL should not be set for non-claude runtime")
	}
	if argsContainPrefix(args, "ANTHROPIC_API_KEY") {
		t.Error("ANTHROPIC_API_KEY should not be set for non-claude runtime")
	}
}

func TestBuildDockerArgs_ClaudeWithProxy(t *testing.T) {
	d := newTestRunner(8081, "secret123", nil)
	rt, _ := d.runtimes.Get("claude")

	args := d.buildDockerArgs("exec-2", rt,
		"/tmp/prompt.txt", "/tmp/prompt.txt",
		"/tmp/sandbox-exec-2", "/tmp/seccomp.json",
		ExecutionRequest{Language: "claude", Code: "hello"},
	)

	if !argsContain(args, "host.docker.internal:host-gateway") {
		t.Error("expected --add-host host.docker.internal:host-gateway")
	}
	if !argsContain(args, "ANTHROPIC_BASE_URL=http://host.docker.internal:8081") {
		t.Error("expected ANTHROPIC_BASE_URL env var")
	}
	if !argsContain(args, "ANTHROPIC_API_KEY=secret123") {
		t.Error("expected ANTHROPIC_API_KEY=secret123")
	}
	// Proxy mode: no token file mount.
	for _, a := range args {
		if strings.Contains(a, "/run/secrets/auth_token") {
			t.Error("auth_token mount should NOT be present in proxy mode")
		}
	}
	if !argsContain(args, "bridge") {
		t.Error("expected --network bridge for claude runtime")
	}
}

func TestBuildDockerArgs_ClaudeWithoutProxy(t *testing.T) {
	d := newTestRunner(0, "", nil)
	rt, _ := d.runtimes.Get("claude")

	args := d.buildDockerArgs("exec-3", rt,
		"/tmp/prompt.txt", "/tmp/prompt.txt",
		"/tmp/sandbox-exec-3", "/tmp/seccomp.json",
		ExecutionRequest{Language: "claude", Code: "hello"},
	)

	// Without proxy, no ANTHROPIC_BASE_URL.
	if argsContainPrefix(args, "ANTHROPIC_BASE_URL") {
		t.Error("ANTHROPIC_BASE_URL should not be set without proxy")
	}
	if !argsContain(args, "bridge") {
		t.Error("expected --network bridge for claude runtime")
	}
	// Claude should not have --read-only.
	if argsContain(args, "--read-only") {
		t.Error("claude runtime should NOT have --read-only")
	}
}

func TestBuildDockerArgs_ClaudeWorkDir(t *testing.T) {
	d := newTestRunner(0, "", nil)
	rt, _ := d.runtimes.Get("claude")

	args := d.buildDockerArgs("exec-4", rt,
		"/tmp/prompt.txt", "/tmp/prompt.txt",
		"/tmp/sandbox-exec-4", "/tmp/seccomp.json",
		ExecutionRequest{Language: "claude", Code: "hello", WorkDir: "/some/path"},
	)

	if !argsContain(args, "/some/path:/workspace:rw") {
		t.Error("expected -v /some/path:/workspace:rw")
	}
}

func TestValidateRequest(t *testing.T) {
	d := newTestRunner(0, "", []string{"/tmp"})

	tests := []struct {
		name    string
		req     ExecutionRequest
		wantErr bool
	}{
		{
			"valid python",
			ExecutionRequest{Language: "python", Code: "print(1)"},
			false,
		},
		{
			"empty code",
			ExecutionRequest{Language: "python", Code: ""},
			true,
		},
		{
			"code > 1MB",
			ExecutionRequest{Language: "python", Code: strings.Repeat("x", 1<<20+1)},
			true,
		},
		{
			"unsupported language",
			ExecutionRequest{Language: "rust", Code: "fn main() {}"},
			true,
		},
		{
			"timeout > max for non-claude",
			ExecutionRequest{Language: "python", Code: "1", Timeout: 2 * time.Minute},
			true,
		},
		{
			"timeout > max for claude",
			ExecutionRequest{Language: "claude", Code: "hello", Timeout: 31 * time.Minute},
			true,
		},
		{
			"invalid env var format (no =)",
			ExecutionRequest{Language: "python", Code: "1", EnvVars: []string{"NOEQUALS"}},
			true,
		},
		{
			"blocked env var LD_PRELOAD",
			ExecutionRequest{Language: "python", Code: "1", EnvVars: []string{"LD_PRELOAD=/lib/evil.so"}},
			true,
		},
		{
			"env var key with special chars",
			ExecutionRequest{Language: "python", Code: "1", EnvVars: []string{"BAD;KEY=val"}},
			true,
		},
		{
			"valid env var",
			ExecutionRequest{Language: "python", Code: "1", EnvVars: []string{"MY_VAR=hello"}},
			false,
		},
		{
			"valid claude request",
			ExecutionRequest{Language: "claude", Code: "summarise this"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := tt.req
			err := d.validateRequest(&req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestBuildDockerArgs_ClaudeDevLimits(t *testing.T) {
	d := newTestRunner(0, "", nil)
	rt, _ := d.runtimes.Get("claude")

	args := d.buildDockerArgs("exec-dev", rt,
		"/tmp/prompt.txt", "/tmp/prompt.txt",
		"/tmp/sandbox-exec-dev", "/tmp/seccomp.json",
		ExecutionRequest{Language: "claude", Code: "hello"},
	)

	// DevLimits(): 4096 MB memory
	if !argsContain(args, "4096m") {
		t.Error("expected --memory 4096m for claude dev limits")
	}
	// DevLimits(): 500 PIDs
	if !argsContain(args, "500") {
		t.Error("expected --pids-limit 500 for claude dev limits")
	}
}

func TestDockerRunner_ClaudeConcurrencyLimit(t *testing.T) {
	d := &DockerRunner{
		runtimes:  runtime.NewRegistry(),
		sem:       make(chan struct{}, 100),
		claudeSem: make(chan struct{}, 2),
	}

	// Fill claude semaphore
	d.claudeSem <- struct{}{}
	d.claudeSem <- struct{}{}

	// Verify main sem still has capacity
	select {
	case d.sem <- struct{}{}:
		<-d.sem // release
	default:
		t.Error("main semaphore should have capacity")
	}

	// Verify claude sem is full
	select {
	case d.claudeSem <- struct{}{}:
		<-d.claudeSem
		t.Error("claude semaphore should be full")
	default:
		// expected
	}

	// Release one slot
	<-d.claudeSem

	// Now should have capacity
	select {
	case d.claudeSem <- struct{}{}:
		<-d.claudeSem
	default:
		t.Error("claude semaphore should have capacity after release")
	}
}
