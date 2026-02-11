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
)

// DockerRunner is the Docker-based sandbox backend (macOS, or Linux without containerd).
type DockerRunner struct {
	runtimes   *runtime.Registry
	sem        chan struct{}
	active     atomic.Int64
	mu         sync.Mutex
	closed     bool
	dockerHost string // resolved DOCKER_HOST (e.g. from Docker context)
}

func NewDockerRunner(maxConcurrent int) *DockerRunner {
	if maxConcurrent < 1 {
		maxConcurrent = 100
	}
	return &DockerRunner{
		runtimes:   runtime.NewRegistry(),
		sem:        make(chan struct{}, maxConcurrent),
		dockerHost: resolveDockerHost(),
	}
}

// resolveDockerHost figures out the Docker socket. On macOS, Docker Desktop uses
// a context-specific socket that child processes don't inherit.
func resolveDockerHost() string {
	if h := os.Getenv("DOCKER_HOST"); h != "" {
		return h
	}

	// Ask the Docker CLI what endpoint it's using
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

	// Validate request
	if err := d.validateRequest(req); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "validate", Err: err}
	}

	// Acquire concurrency slot
	select {
	case d.sem <- struct{}{}:
		defer func() { <-d.sem }()
	case <-ctx.Done():
		return nil, &ExecutionError{ExecID: execID, Op: "acquire_slot", Err: ctx.Err()}
	}

	d.active.Add(1)
	defer d.active.Add(-1)

	// Set up timeout
	timeout := req.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Get runtime config
	rt, err := d.runtimes.Get(req.Language)
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "get_runtime", Err: err}
	}

	// Write code to a temp file on the host
	hostDir, err := os.MkdirTemp("", "sandbox-"+execID+"-*")
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "create_temp_dir", Err: err}
	}
	defer os.RemoveAll(hostDir)

	codeFile := filepath.Join(hostDir, "code"+rt.FileExtension())
	if err := os.WriteFile(codeFile, []byte(req.Code), 0600); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "write_code", Err: err}
	}
	// Container runs as nobody (UID 65534), so the file must be world-readable
	if err := os.Chmod(codeFile, 0444); err != nil { // #nosec G302 -- world-readable needed: container runs as nobody (UID 65534)
		return nil, &ExecutionError{ExecID: execID, Op: "chmod_code", Err: err}
	}

	containerCodePath := "/workspace/code" + rt.FileExtension()

	// Build docker run arguments
	args := d.buildDockerArgs(execID, rt, codeFile, containerCodePath, req)

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
			// Timeout
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
			// Exit code 137 = killed (OOM or PID limit)
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
	req ExecutionRequest,
) []string {
	limits := req.Limits
	if limits == (ResourceLimits{}) {
		limits = DefaultLimits()
	}

	args := []string{
		"run", "--rm",
		"--name", "sandbox-" + execID,
		"--read-only",
		"--network", "none",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--memory", fmt.Sprintf("%dm", limits.MemoryMB),
		"--memory-swap", fmt.Sprintf("%dm", limits.MemoryMB),
		"--pids-limit", fmt.Sprintf("%d", limits.PidsLimit),
		"--cpus", fmt.Sprintf("%.1f", float64(limits.CPUShares)/1024.0),
		"--tmpfs", fmt.Sprintf("/tmp:rw,nosuid,nodev,size=%dm", limits.DiskMB),
		"-v", fmt.Sprintf("%s:%s:ro", hostCodeFile, containerCodePath),
		"--user", "65534:65534",
		"-e", "HOME=/tmp",
		"-e", "LANG=C.UTF-8",
		"-e", "SANDBOX=true",
	}

	if req.NetworkEnabled {
		for i, a := range args {
			if a == "--network" && i+1 < len(args) {
				args[i+1] = "bridge"
				break
			}
		}
	}

	args = append(args, rt.Image())
	args = append(args, rt.Command(containerCodePath)...)

	return args
}

func (d *DockerRunner) validateRequest(req ExecutionRequest) error {
	if req.Code == "" {
		return fmt.Errorf("%w: code is empty", ErrInvalidRequest)
	}
	if len(req.Code) > 1<<20 {
		return fmt.Errorf("%w: code exceeds 1MB limit", ErrInvalidRequest)
	}
	if _, err := d.runtimes.Get(req.Language); err != nil {
		return fmt.Errorf("%w: %s", ErrUnsupportedLang, req.Language)
	}
	if req.Timeout > 60*time.Second {
		return fmt.Errorf("%w: timeout exceeds 60s maximum", ErrInvalidRequest)
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
	return nil
}
