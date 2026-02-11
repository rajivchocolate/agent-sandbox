package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/runtime"
	"safe-agent-sandbox/pkg/seccomp"
)

// envBlocklist contains env var keys that must never be passed into a container.
var envBlocklist = map[string]bool{
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"HTTP_PROXY":      true,
	"HTTPS_PROXY":     true,
	"NODE_OPTIONS":    true,
	"PYTHONPATH":      true,
	"PATH":            true,
	"HOME":            true,
	"USER":            true,
}

// sensitivePathPrefixes are directories that must never be mounted as WorkDir.
var sensitivePathPrefixes = []string{"/etc", "/var", "/root"}

// sensitiveHomeDirs are subdirectories of a home folder that indicate sensitive secrets.
var sensitiveHomeDirs = []string{".ssh", ".aws", ".gnupg", ".claude"}

// DockerRunner is the Docker-based sandbox backend (macOS, or Linux without containerd).
type DockerRunner struct {
	runtimes      *runtime.Registry
	sem           chan struct{}
	active        atomic.Int64
	wg            sync.WaitGroup
	mu            sync.Mutex
	closed        bool
	dockerHost    string   // resolved DOCKER_HOST (e.g. from Docker context)
	allowedRoots  []string // WorkDir must be under one of these
	proxyPort     int      // >0 means auth proxy is active; skip token-via-file
	proxySecret   string   // shared secret containers present to the auth proxy
	cancelCleanup context.CancelFunc
}

func NewDockerRunner(maxConcurrent int, allowedRoots []string, proxyPort int, proxySecret string) *DockerRunner {
	if maxConcurrent < 1 {
		maxConcurrent = 100
	}
	d := &DockerRunner{
		runtimes:     runtime.NewRegistry(),
		sem:          make(chan struct{}, maxConcurrent),
		dockerHost:   resolveDockerHost(),
		allowedRoots: allowedRoots,
		proxyPort:    proxyPort,
		proxySecret:  proxySecret,
	}

	ctx, cancel := context.WithCancel(context.Background())
	d.cancelCleanup = cancel
	go d.orphanCleanupLoop(ctx)

	return d
}

// orphanCleanupLoop periodically kills orphaned sandbox containers that survived server crashes.
func (d *DockerRunner) orphanCleanupLoop(ctx context.Context) {
	// Run once on startup
	d.cleanupOrphans()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.cleanupOrphans()
		case <-ctx.Done():
			return
		}
	}
}

func (d *DockerRunner) cleanupOrphans() {
	cmd := exec.Command("docker", "ps", "--filter", "name=sandbox-", "-q") // #nosec G204 -- no user input
	if d.dockerHost != "" {
		cmd.Env = append(os.Environ(), "DOCKER_HOST="+d.dockerHost)
	}
	out, err := cmd.Output()
	if err != nil {
		return
	}
	ids := strings.Fields(strings.TrimSpace(string(out)))
	for _, id := range ids {
		log.Warn().Str("container_id", id).Msg("killing orphaned sandbox container")
		kill := exec.Command("docker", "rm", "-f", id) // #nosec G204 -- id from docker ps
		if d.dockerHost != "" {
			kill.Env = append(os.Environ(), "DOCKER_HOST="+d.dockerHost)
		}
		_ = kill.Run()
	}
}

// resolveDockerHost figures out the Docker socket. On macOS, Docker Desktop uses
// a context-specific socket that child processes don't inherit.
func resolveDockerHost() string {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return h
	}

	out, err := exec.Command("docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}").Output()
	if err == nil {
		host := strings.TrimSpace(string(out))
		if host != "" {
			log.Debug().Str("docker_host", host).Msg("resolved Docker host from context")
			return host
		}
	}

	return ""
}

func (d *DockerRunner) Execute(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	var stdout, stderr bytes.Buffer
	return d.executeInternal(ctx, req, &stdout, &stderr)
}

func (d *DockerRunner) ExecuteStreaming(ctx context.Context, req ExecutionRequest, stdout, stderr io.Writer) (*ExecutionResult, error) {
	return d.executeInternal(ctx, req, stdout, stderr)
}

func (d *DockerRunner) executeInternal(ctx context.Context, req ExecutionRequest, stdout, stderr io.Writer) (*ExecutionResult, error) {
	execID := uuid.New().String()
	codeHash := fmt.Sprintf("%x", sha256.Sum256([]byte(req.Code)))

	logger := log.With().
		Str("exec_id", execID).
		Str("language", req.Language).
		Str("code_hash", codeHash[:16]).
		Logger()

	logger.Info().Msg("docker execution requested")

	if err := d.validateRequest(&req); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "validate", Err: err}
	}

	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	case <-ctx.Done():
		return nil, &ExecutionError{ExecID: execID, Op: "acquire_slot", Err: ctx.Err()}
	}

	d.wg.Add(1)
	defer d.wg.Done()
	d.active.Add(1)
	defer d.active.Add(-1)

	timeout := req.Timeout
	if timeout == 0 {
		if req.Language == "claude" {
			timeout = 5 * time.Minute
		} else {
			timeout = 10 * time.Second
		}
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	rt, err := d.runtimes.Get(req.Language)
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "get_runtime", Err: err}
	}

	hostDir, err := os.MkdirTemp("", "sandbox-"+execID+"-*")
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "create_temp_dir", Err: err}
	}
	defer os.RemoveAll(hostDir)

	codeFile := filepath.Join(hostDir, "code"+rt.FileExtension())
	if err := os.WriteFile(codeFile, []byte(req.Code), 0600); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "write_code", Err: err}
	}
	if err := os.Chmod(codeFile, 0444); err != nil { // world-readable: container runs as nobody
		return nil, &ExecutionError{ExecID: execID, Op: "chmod_code", Err: err}
	}

	containerCodePath := "/workspace/code" + rt.FileExtension()
	if rt.Name() == "claude" {
		containerCodePath = "/tmp/prompt" + rt.FileExtension()
	}

	// Write auth token to a secret file (not env var) so it's not visible via docker inspect / /proc/*/environ.
	// When the auth proxy is active (proxyPort > 0), the token never enters the container at all.
	isClaude := rt.Name() == "claude"
	if isClaude && d.proxyPort == 0 {
		for _, key := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"} {
			if v := os.Getenv(key); v != "" {
				tokenPath := filepath.Join(hostDir, "auth_token")
				if err := os.WriteFile(tokenPath, []byte(v), 0400); err != nil { // #nosec G306 -- mode 0400
					return nil, &ExecutionError{ExecID: execID, Op: "write_token", Err: err}
				}
				break
			}
		}
	}

	// Write seccomp profile to temp file for Docker's --security-opt.
	var seccompPath string
	{
		var profileJSON []byte
		var profileErr error
		if isClaude || req.NetworkEnabled {
			profileJSON, profileErr = seccomp.DockerNetworkProfileJSON()
		} else {
			profileJSON, profileErr = seccomp.DockerProfileJSON()
		}
		if profileErr != nil {
			return nil, &ExecutionError{ExecID: execID, Op: "seccomp_profile", Err: profileErr}
		}
		seccompFile := filepath.Join(hostDir, "seccomp.json")
		if err := os.WriteFile(seccompFile, profileJSON, 0600); err != nil {
			return nil, &ExecutionError{ExecID: execID, Op: "write_seccomp", Err: err}
		}
		seccompPath = seccompFile
	}

	args := d.buildDockerArgs(execID, rt, codeFile, containerCodePath, hostDir, seccompPath, req)

	start := time.Now()

	cmd := exec.CommandContext(execCtx, "docker", args...) // #nosec G204 -- args built internally by buildDockerArgs, not from raw user input

	if d.dockerHost != "" {
		cmd.Env = append(os.Environ(), "DOCKER_HOST="+d.dockerHost)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = io.MultiWriter(&stdoutBuf, stdout)
	cmd.Stderr = io.MultiWriter(&stderrBuf, stderr)

	logger.Info().Strs("args", args[:5]).Msg("starting docker container")

	err = cmd.Run()
	duration := time.Since(start)

	var exitCode int
	var securityEvents []SecurityEvent

	if err != nil {
		if execCtx.Err() == context.DeadlineExceeded {
			securityEvents = append(securityEvents, SecurityEvent{
				Type:   "timeout",
				Detail: fmt.Sprintf("execution exceeded %s timeout", timeout),
			})
			return &ExecutionResult{
				ID:             execID,
				Output:         truncateOutput(stdoutBuf.String(), 1<<20),
				Stderr:         truncateOutput(stderrBuf.String(), 256*1024),
				ExitCode:       -1,
				Duration:       duration,
				SecurityEvents: securityEvents,
				CodeHash:       codeHash,
			}, ErrTimeout
		}

		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
			if exitCode == 137 {
				securityEvents = append(securityEvents, SecurityEvent{
					Type:   "oom_kill",
					Detail: "process killed (OOM or resource limit)",
				})
			}
		} else {
			return nil, &ExecutionError{ExecID: execID, Op: "docker_run", Err: err}
		}
	}

	logger.Info().
		Int("exit_code", exitCode).
		Dur("duration", duration).
		Msg("docker execution completed")

	return &ExecutionResult{
		ID:             execID,
		Output:         truncateOutput(stdoutBuf.String(), 1<<20),
		Stderr:         truncateOutput(stderrBuf.String(), 256*1024),
		ExitCode:       exitCode,
		Duration:       duration,
		SecurityEvents: securityEvents,
		CodeHash:       codeHash,
	}, nil
}

func (d *DockerRunner) buildDockerArgs(
	execID string,
	rt runtime.Runtime,
	hostCodeFile, containerCodePath string,
	hostDir, seccompPath string,
	req ExecutionRequest,
) []string {
	isClaude := rt.Name() == "claude"

	limits := req.Limits
	if limits == (ResourceLimits{}) {
		if isClaude {
			limits = claudeDefaultLimits()
		} else {
			limits = DefaultLimits()
		}
	}

	network := "none"
	if req.NetworkEnabled || isClaude {
		network = "bridge"
	}

	user := "65534:65534"
	home := "/tmp"
	if isClaude {
		user = "1000:1000"
		home = "/home/node"
	}

	args := []string{
		"run", "--rm",
		"--name", "sandbox-" + execID,
		"--network", network,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--security-opt", "seccomp=" + seccompPath,
		"--memory", fmt.Sprintf("%dm", limits.MemoryMB),
		"--memory-swap", fmt.Sprintf("%dm", limits.MemoryMB),
		"--pids-limit", fmt.Sprintf("%d", limits.PidsLimit),
		"--cpus", fmt.Sprintf("%.1f", float64(limits.CPUShares)/1024.0),
		"--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,size=%dm", limits.DiskMB),
		"-v", fmt.Sprintf("%s:%s:ro", hostCodeFile, containerCodePath),
		"--user", user,
		"-e", "HOME=" + home,
		"-e", "LANG=C.UTF-8",
		"-e", "SANDBOX=true",
	}

	// Claude needs a writable rootfs (Node.js/npm write to global cache dirs at startup).
	// Other runtimes get a read-only rootfs for tighter isolation.
	if !isClaude {
		args = append(args, "--read-only")
	}

	if isClaude {
		if req.WorkDir != "" {
			args = append(args,
				"-v", fmt.Sprintf("%s:/workspace:rw", req.WorkDir),
			)
		}

		if d.proxyPort > 0 {
			// Auth proxy mode: route API traffic through the host proxy.
			// The container gets a proxy secret as its "API key" — the proxy
			// validates it before forwarding with the real token. The secret
			// is worthless against api.anthropic.com directly.
			args = append(args,
				"--add-host", "host.docker.internal:host-gateway",
				"-e", fmt.Sprintf("ANTHROPIC_BASE_URL=http://host.docker.internal:%d", d.proxyPort),
				"-e", "ANTHROPIC_API_KEY="+d.proxySecret,
			)
		} else {
			// Legacy mode: mount auth token as a secret file.
			tokenPath := filepath.Join(hostDir, "auth_token")
			if _, err := os.Stat(tokenPath); err == nil {
				args = append(args,
					"-v", fmt.Sprintf("%s:/run/secrets/auth_token:ro", tokenPath),
				)
			}
		}
	}

	for _, env := range req.EnvVars {
		args = append(args, "-e", env)
	}

	args = append(args, rt.Image())
	args = append(args, rt.Command(containerCodePath)...)

	return args
}

func claudeDefaultLimits() ResourceLimits {
	return ResourceLimits{
		CPUShares: 2048,
		MemoryMB:  1024,
		PidsLimit: 200,
		DiskMB:    500,
	}
}

func (d *DockerRunner) validateRequest(req *ExecutionRequest) error {
	if req.Code == "" {
		return fmt.Errorf("%w: code is empty", ErrInvalidRequest)
	}
	if len(req.Code) > 1<<20 {
		return fmt.Errorf("%w: code exceeds 1MB limit", ErrInvalidRequest)
	}
	if _, err := d.runtimes.Get(req.Language); err != nil {
		return fmt.Errorf("%w: %s", ErrUnsupportedLang, req.Language)
	}
	maxTimeout := 60 * time.Second
	if req.Language == "claude" {
		maxTimeout = 5 * time.Minute
	}
	if req.Timeout > maxTimeout {
		return fmt.Errorf("%w: timeout exceeds %s maximum", ErrInvalidRequest, maxTimeout)
	}
	if req.WorkDir != "" {
		// Resolve symlinks to prevent TOCTOU race — store the real path back into req.
		realPath, err := filepath.EvalSymlinks(req.WorkDir)
		if err != nil {
			return fmt.Errorf("%w: work_dir is not valid", ErrInvalidRequest)
		}
		info, err := os.Stat(realPath)
		if err != nil || !info.IsDir() {
			return fmt.Errorf("%w: work_dir is not a valid directory", ErrInvalidRequest)
		}
		req.WorkDir = realPath

		// Block known sensitive prefixes
		for _, prefix := range sensitivePathPrefixes {
			if strings.HasPrefix(realPath, prefix+"/") || realPath == prefix {
				return fmt.Errorf("%w: work_dir %q is under a sensitive path", ErrInvalidRequest, prefix)
			}
		}
		// Block home directories containing sensitive subdirs
		for _, dir := range sensitiveHomeDirs {
			if strings.Contains(realPath, "/"+dir+"/") || strings.HasSuffix(realPath, "/"+dir) {
				return fmt.Errorf("%w: work_dir contains sensitive directory %q", ErrInvalidRequest, dir)
			}
		}

		// Check WorkDir is under an allowed root
		if len(d.allowedRoots) > 0 {
			allowed := false
			for _, root := range d.allowedRoots {
				if strings.HasPrefix(realPath, root+"/") || realPath == root {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("%w: work_dir is not under an allowed root", ErrInvalidRequest)
			}
		} else {
			return fmt.Errorf("%w: no allowed_workdir_roots configured; WorkDir mounts are disabled", ErrInvalidRequest)
		}
	}
	for _, env := range req.EnvVars {
		if !strings.Contains(env, "=") {
			return fmt.Errorf("%w: env var must be KEY=VALUE format", ErrInvalidRequest)
		}
		key := env[:strings.Index(env, "=")]
		for _, c := range key {
			if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return fmt.Errorf("%w: env var key contains invalid characters", ErrInvalidRequest)
			}
		}
		if envBlocklist[strings.ToUpper(key)] {
			return fmt.Errorf("%w: env var %q is blocked for security reasons", ErrInvalidRequest, key)
		}
	}
	if req.Limits != (ResourceLimits{}) {
		if err := req.Limits.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (d *DockerRunner) ActiveCount() int64 {
	return d.active.Load()
}

func (d *DockerRunner) Close() error {
	d.mu.Lock()
	d.closed = true
	d.mu.Unlock()

	if d.cancelCleanup != nil {
		d.cancelCleanup()
	}

	// Wait up to 30s for active executions to drain.
	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		log.Info().Msg("all docker executions drained")
	case <-time.After(30 * time.Second):
		log.Warn().Int64("active", d.active.Load()).Msg("timed out waiting for docker executions to drain")
	}
	return nil
}
