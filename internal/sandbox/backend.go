package sandbox

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"

	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/config"
)

type Backend interface {
	Execute(ctx context.Context, req ExecutionRequest) (*ExecutionResult, error)
	ExecuteStreaming(ctx context.Context, req ExecutionRequest, stdout, stderr io.Writer) (*ExecutionResult, error)
	Close() error
}

// NewBackend picks the best available backend: containerd on Linux, Docker elsewhere.
func NewBackend(ctx context.Context, cfg *config.Config) (Backend, error) {
	preference := cfg.Sandbox.Backend
	if preference == "" {
		preference = "auto"
	}

	switch preference {
	case "containerd":
		return newContainerdBackend(ctx, cfg)
	case "docker":
		return newDockerBackend(cfg)
	case "auto":
		if runtime.GOOS == "linux" {
			backend, err := newContainerdBackend(ctx, cfg)
			if err == nil {
				log.Info().Msg("using containerd backend")
				return backend, nil
			}
			log.Warn().Err(err).Msg("containerd unavailable, trying Docker")
		}

		backend, err := newDockerBackend(cfg)
		if err == nil {
			log.Info().Msg("using Docker backend")
			return backend, nil
		}

		return nil, fmt.Errorf("no sandbox backend available: install Docker Desktop (macOS/Windows) or containerd (Linux)")
	default:
		return nil, fmt.Errorf("unknown backend %q: must be auto, containerd, or docker", preference)
	}
}

func newContainerdBackend(ctx context.Context, cfg *config.Config) (Backend, error) {
	client, err := NewClient(ctx, cfg.Sandbox.ContainerdSocket, cfg.Sandbox.Namespace)
	if err != nil {
		return nil, err
	}

	runner, err := NewRunner(ctx, client, cfg.Sandbox.MaxConcurrent)
	if err != nil {
		_ = client.Close()
		return nil, err
	}

	cleaned, err := runner.CleanupOrphaned(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to cleanup orphaned containers")
	} else if cleaned > 0 {
		log.Info().Int("count", cleaned).Msg("cleaned orphaned containers on startup")
	}

	return runner, nil
}

func newDockerBackend(cfg *config.Config) (Backend, error) {
	if _, err := exec.LookPath("docker"); err != nil {
		return nil, fmt.Errorf("docker not found in PATH: %w", err)
	}

	if err := exec.Command("docker", "info").Run(); err != nil {
		return nil, fmt.Errorf("docker daemon not reachable: %w", err)
	}

	return NewDockerRunner(cfg.Sandbox.MaxConcurrent, cfg.Sandbox.AllowedWorkdirRoots), nil
}
