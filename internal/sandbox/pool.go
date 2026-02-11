package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/rs/zerolog/log"
)

// Pool maintains pre-warmed containers for sub-10ms startup (containerd only).
type Pool struct {
	client   *Client
	runtimes []string

	mu       sync.Mutex
	pools    map[string]chan containerd.Container
	minIdle  int
	maxIdle  int
	maxAge   time.Duration

	done chan struct{}
	wg   sync.WaitGroup
}

type PoolConfig struct {
	MinIdle     int           // Minimum warm containers per runtime
	MaxIdle     int           // Maximum warm containers per runtime
	RefillDelay time.Duration // How often to top-up the pool
	MaxAge      time.Duration // Max container age before recycling
}

func NewPool(client *Client, runtimes []string, cfg PoolConfig) *Pool {
	if cfg.MinIdle < 1 {
		cfg.MinIdle = 2
	}
	if cfg.MaxIdle < cfg.MinIdle {
		cfg.MaxIdle = cfg.MinIdle * 2
	}
	if cfg.RefillDelay == 0 {
		cfg.RefillDelay = 500 * time.Millisecond
	}
	if cfg.MaxAge == 0 {
		cfg.MaxAge = 5 * time.Minute
	}

	p := &Pool{
		client:   client,
		runtimes: runtimes,
		pools:    make(map[string]chan containerd.Container),
		minIdle:  cfg.MinIdle,
		maxIdle:  cfg.MaxIdle,
		maxAge:   cfg.MaxAge,
		done:     make(chan struct{}),
	}

	for _, rt := range runtimes {
		p.pools[rt] = make(chan containerd.Container, cfg.MaxIdle)
	}

	return p
}

func (p *Pool) Start(ctx context.Context) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.refillLoop(ctx)
	}()

	log.Info().
		Int("min_idle", p.minIdle).
		Int("max_idle", p.maxIdle).
		Strs("runtimes", p.runtimes).
		Msg("container pool started")
}

func (p *Pool) Acquire(runtime string) containerd.Container {
	p.mu.Lock()
	ch, ok := p.pools[runtime]
	p.mu.Unlock()

	if !ok {
		return nil
	}

	select {
	case container := <-ch:
		log.Debug().
			Str("runtime", runtime).
			Str("container_id", container.ID()).
			Msg("acquired warm container from pool")
		return container
	default:
		return nil
	}
}

func (p *Pool) Size(runtime string) int {
	p.mu.Lock()
	ch, ok := p.pools[runtime]
	p.mu.Unlock()

	if !ok {
		return 0
	}
	return len(ch)
}

func (p *Pool) Stop(ctx context.Context) {
	close(p.done)
	p.wg.Wait()

	p.mu.Lock()
	defer p.mu.Unlock()

	for rt, ch := range p.pools {
		close(ch)
		var count int
		for container := range ch {
			if err := container.Delete(ctx, containerd.WithSnapshotCleanup); err != nil {
				log.Warn().Err(err).Str("runtime", rt).Msg("failed to cleanup pooled container")
			}
			count++
		}
		if count > 0 {
			log.Info().Str("runtime", rt).Int("count", count).Msg("drained pool containers")
		}
	}
}

func (p *Pool) refillLoop(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-p.done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refill(ctx)
		}
	}
}

func (p *Pool) refill(ctx context.Context) {
	for _, rt := range p.runtimes {
		p.mu.Lock()
		ch := p.pools[rt]
		current := len(ch)
		p.mu.Unlock()

		if current >= p.minIdle {
			continue
		}

		needed := p.minIdle - current
		for range needed {
			select {
			case <-p.done:
				return
			default:
			}

			// TODO: create warm container with sleep entrypoint, swap process on Acquire
			_ = fmt.Sprintf("creating warm container for %s", rt)
		}
	}
}
