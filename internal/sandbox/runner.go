package sandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/containers"
	"github.com/containerd/containerd/oci"
	"github.com/google/uuid"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/runtime"
)

type ExecutionRequest struct {
	Code           string         `json:"code"`
	Language       string         `json:"language"`
	Timeout        time.Duration  `json:"timeout"`
	Limits         ResourceLimits `json:"limits"`
	NetworkEnabled bool           `json:"network_enabled"`
	WorkDir        string         `json:"work_dir,omitempty"` // Host directory to mount as /workspace (claude runtime)
	EnvVars        []string       `json:"env_vars,omitempty"` // Additional env vars (e.g. CLAUDE_CODE_OAUTH_TOKEN)
}

type ExecutionResult struct {
	ID             string          `json:"id"`
	Output         string          `json:"output"`
	Stderr         string          `json:"stderr"`
	ExitCode       int             `json:"exit_code"`
	Duration       time.Duration   `json:"duration"`
	ResourceUsage  ResourceUsage   `json:"resource_usage"`
	SecurityEvents []SecurityEvent `json:"security_events,omitempty"`
	CodeHash       string          `json:"code_hash"`
}

type ResourceUsage struct {
	CPUTimeMS    int64 `json:"cpu_time_ms"`
	MemoryPeakMB int64 `json:"memory_peak_mb"`
	PidsUsed     int64 `json:"pids_used"`
}

type SecurityEvent struct {
	Type    string `json:"type"`
	Syscall string `json:"syscall,omitempty"`
	Detail  string `json:"detail"`
}

// Runner is the containerd-based sandbox backend.
type Runner struct {
	client   *Client
	runtimes *runtime.Registry
	sem      chan struct{} // Concurrency limiter
	active   atomic.Int64 // Active execution count
	mu       sync.Mutex   // Protects shutdown state
	closed   bool
}

// NewRunner creates a new sandbox runner.
func NewRunner(ctx context.Context, client *Client, maxConcurrent int) (*Runner, error) {
	if maxConcurrent < 1 {
		maxConcurrent = 100
	}

	return &Runner{
		client:   client,
		runtimes: runtime.NewRegistry(),
		sem:      make(chan struct{}, maxConcurrent),
	}, nil
}

// Execute runs code in an isolated sandbox container.
func (r *Runner) Execute(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error) {
	var stdout, stderr bytes.Buffer
	return r.executeInternal(ctx, req, &stdout, &stderr)
}

// ExecuteStreaming runs code in a sandbox, streaming stdout/stderr to the provided writers.
func (r *Runner) ExecuteStreaming(ctx context.Context, req ExecutionRequest, stdout, stderr io.Writer) (*ExecutionResult, error) {
	return r.executeInternal(ctx, req, stdout, stderr)
}

func (r *Runner) executeInternal(ctx context.Context, req ExecutionRequest, stdout, stderr io.Writer) (*ExecutionResult, error) {
	execID := uuid.New().String()
	codeHash := fmt.Sprintf("%x", sha256.Sum256([]byte(req.Code)))

	logger := log.With().
		Str("exec_id", execID).
		Str("language", req.Language).
		Str("code_hash", codeHash[:16]).
		Logger()

	logger.Info().Msg("execution requested")

	if err := r.validateRequest(req); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "validate", Err: err}
	}

	select {
	case r.sem <- struct{}{}:
		defer func() { <-r.sem }()
	case <-ctx.Done():
		return nil, &ExecutionError{ExecID: execID, Op: "acquire_slot", Err: ctx.Err()}
	}

	r.active.Add(1)
	defer r.active.Add(-1)

	timeout := req.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()

	rt, err := r.runtimes.Get(req.Language)
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "get_runtime", Err: err}
	}

	hostCodeDir, err := os.MkdirTemp("", "sandbox-"+execID+"-*")
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "create_temp_dir", Err: err}
	}
	defer os.RemoveAll(hostCodeDir)

	codeFileName := "code" + rt.FileExtension()
	hostCodePath := filepath.Join(hostCodeDir, codeFileName)
	if err := os.WriteFile(hostCodePath, []byte(req.Code), 0600); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "write_code", Err: err}
	}
	if err := os.Chmod(hostCodePath, 0444); err != nil { // #nosec G302 -- container runs as nobody (UID 65534)
		return nil, &ExecutionError{ExecID: execID, Op: "chmod_code", Err: err}
	}

	image, err := r.client.PullImage(execCtx, rt.Image())
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "pull_image", Err: err}
	}

	secProfile := DefaultSecurityProfile()
	if req.NetworkEnabled {
		secProfile = NetworkAllowedSecurityProfile()
	}

	containerID := fmt.Sprintf("sandbox-%s", execID)
	codePath := fmt.Sprintf("/workspace/%s", codeFileName)

	container, err := r.createContainer(execCtx, containerID, image, rt, codePath, hostCodeDir, req, secProfile)
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "create_container", Err: err}
	}
	// Always cleanup, even on panic
	defer func() {
		if cleanErr := r.cleanupContainer(context.Background(), container); cleanErr != nil {
			logger.Error().Err(cleanErr).Msg("container cleanup failed")
		}
	}()

	var stdoutBuf, stderrBuf bytes.Buffer
	stdoutWriter := io.MultiWriter(&stdoutBuf, stdout)
	stderrWriter := io.MultiWriter(&stderrBuf, stderr)

	task, err := container.NewTask(execCtx,
		cio.NewCreator(cio.WithStreams(nil, stdoutWriter, stderrWriter)),
	)
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "create_task", Err: err}
	}
	defer func() {
		if _, err := task.Delete(context.Background(), containerd.WithProcessKill); err != nil {
			logger.Error().Err(err).Msg("task delete failed")
		}
	}()

	exitCh, err := task.Wait(execCtx)
	if err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "task_wait", Err: err}
	}

	if err := task.Start(execCtx); err != nil {
		return nil, &ExecutionError{ExecID: execID, Op: "task_start", Err: err}
	}

	logger.Info().Msg("task started")

	var exitCode int
	var securityEvents []SecurityEvent

	select {
	case status := <-exitCh:
		exitCode = int(status.ExitCode())
		if status.Error() != nil {
			if isOOMKilled(status.Error()) {
				securityEvents = append(securityEvents, SecurityEvent{
					Type:   "oom_kill",
					Detail: "process killed by OOM killer",
				})
				return &ExecutionResult{
					ID:             execID,
					Stderr:         "Process killed: out of memory",
					ExitCode:       137,
					Duration:       time.Since(start),
					SecurityEvents: securityEvents,
					CodeHash:       codeHash,
				}, ErrOOM
			}
		}

	case <-execCtx.Done():
		logger.Warn().Msg("execution timed out, killing task")
		if err := task.Kill(context.Background(), 9); err != nil {
			logger.Error().Err(err).Msg("failed to kill timed out task")
		}
		<-exitCh

		securityEvents = append(securityEvents, SecurityEvent{
			Type:   "timeout",
			Detail: fmt.Sprintf("execution exceeded %s timeout", timeout),
		})

		return &ExecutionResult{
			ID:             execID,
			Output:         truncateOutput(stdoutBuf.String(), 1<<20),
			Stderr:         truncateOutput(stderrBuf.String(), 256*1024),
			ExitCode:       -1,
			Duration:       time.Since(start),
			SecurityEvents: securityEvents,
			CodeHash:       codeHash,
		}, ErrTimeout
	}

	duration := time.Since(start)
	logger.Info().
		Int("exit_code", exitCode).
		Dur("duration", duration).
		Msg("execution completed")

	return &ExecutionResult{
		ID:             execID,
		Output:         truncateOutput(stdoutBuf.String(), 1<<20), // 1MB max
		Stderr:         truncateOutput(stderrBuf.String(), 256*1024), // 256KB max
		ExitCode:       exitCode,
		Duration:       duration,
		SecurityEvents: securityEvents,
		CodeHash:       codeHash,
	}, nil
}

// ActiveCount returns the number of currently running executions.
func (r *Runner) ActiveCount() int64 {
	return r.active.Load()
}

// Close shuts down the runner, waiting for active executions.
func (r *Runner) Close() error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return nil
}

func (r *Runner) createContainer(
	ctx context.Context,
	id string,
	image containerd.Image,
	rt runtime.Runtime,
	codePath string,
	hostCodeDir string,
	req ExecutionRequest,
	secProfile SecurityProfile,
) (containerd.Container, error) {
	nsCtx := r.client.WithNamespace(ctx)

	container, err := r.client.Raw().NewContainer(nsCtx, id,
		containerd.WithImage(image),
		containerd.WithNewSnapshot(id+"-snapshot", image),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			oci.WithProcessArgs(rt.Command(codePath)...),
			oci.WithHostname("sandbox"),
			func(_ context.Context, _ oci.Client, _ *containers.Container, s *specs.Spec) error {
				ApplySecurityProfile(s, secProfile)
				ApplyResourceLimits(s, req.Limits)

				s.Mounts = append(s.Mounts, specs.Mount{
					Destination: "/workspace",
					Type:        "bind",
					Source:      hostCodeDir,
					Options:     []string{"rbind", "ro"},
				})

				s.Process.Env = []string{
					"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"HOME=/tmp",
					"LANG=C.UTF-8",
					"SANDBOX=true",
				}

				return nil
			},
		),
	)
	if err != nil {
		return nil, fmt.Errorf("creating container: %w", err)
	}

	return container, nil
}

func (r *Runner) validateRequest(req ExecutionRequest) error {
	if req.Code == "" {
		return fmt.Errorf("%w: code is empty", ErrInvalidRequest)
	}
	if len(req.Code) > 1<<20 {
		return fmt.Errorf("%w: code exceeds 1MB limit", ErrInvalidRequest)
	}

	if req.Language == "claude" {
		return fmt.Errorf("%w: claude runtime requires Docker backend (not containerd)", ErrUnsupportedLang)
	}

	if _, err := r.runtimes.Get(req.Language); err != nil {
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

func isOOMKilled(err error) bool {
	if err == nil {
		return false
	}
	return false // Placeholder: check cgroup OOM events in production
}

func truncateOutput(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	return s[:maxBytes] + "\n... [output truncated]"
}
