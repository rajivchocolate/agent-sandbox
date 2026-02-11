package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/rs/zerolog/log"
)

func (r *Runner) cleanupContainer(ctx context.Context, container containerd.Container) error {
	if container == nil {
		return nil
	}

	id := container.ID()
	logger := log.With().Str("container_id", id).Logger()

	cleanupCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	cleanupCtx = r.client.WithNamespace(cleanupCtx)

	if task, err := container.Task(cleanupCtx, nil); err == nil {
		if status, err := task.Status(cleanupCtx); err == nil && status.Status != containerd.Stopped {
			logger.Debug().Msg("killing running task")
			_ = task.Kill(cleanupCtx, 9)

			waitCtx, waitCancel := context.WithTimeout(cleanupCtx, 5*time.Second)
			defer waitCancel()
			exitCh, _ := task.Wait(waitCtx)
			if exitCh != nil {
				select {
				case <-exitCh:
				case <-waitCtx.Done():
					logger.Warn().Msg("timed out waiting for task to stop")
				}
			}
		}

		if _, err := task.Delete(cleanupCtx, containerd.WithProcessKill); err != nil {
			if !errdefs.IsNotFound(err) {
				logger.Warn().Err(err).Msg("failed to delete task")
			}
		}
	}

	if err := container.Delete(cleanupCtx, containerd.WithSnapshotCleanup); err != nil {
		if !errdefs.IsNotFound(err) {
			logger.Error().Err(err).Msg("failed to delete container")
			return fmt.Errorf("deleting container %s: %w", id, err)
		}
	}

	logger.Debug().Msg("container cleaned up")
	return nil
}

// CleanupOrphaned removes sandbox containers left over from previous runs.
func (r *Runner) CleanupOrphaned(ctx context.Context) (int, error) {
	nsCtx := r.client.WithNamespace(ctx)

	containers, err := r.client.Raw().Containers(nsCtx)
	if err != nil {
		return 0, fmt.Errorf("listing containers: %w", err)
	}

	var cleaned int
	for _, c := range containers {
		id := c.ID()
		if !strings.HasPrefix(id, "sandbox-") {
			continue
		}

		logger := log.With().Str("container_id", id).Logger()
		logger.Info().Msg("cleaning up orphaned sandbox container")

		if err := r.cleanupContainer(ctx, c); err != nil {
			logger.Error().Err(err).Msg("failed to clean orphaned container")
			continue
		}
		cleaned++
	}

	if cleaned > 0 {
		log.Info().Int("count", cleaned).Msg("cleaned up orphaned containers")
	}

	return cleaned, nil
}

func (r *Runner) GarbageCollect(ctx context.Context) error {
	nsCtx := r.client.WithNamespace(ctx)

	cs := r.client.Raw().ContentStore()
	if cs == nil {
		return nil
	}
	_ = nsCtx // GC is triggered through lease management; this is a no-op placeholder
	return nil
}
