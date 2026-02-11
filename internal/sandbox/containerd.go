package sandbox

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/namespaces"
	"github.com/rs/zerolog/log"
)

// Client wraps the containerd client with connection management and health checking.
type Client struct {
	inner     *containerd.Client
	socket    string
	namespace string

	mu     sync.RWMutex
	closed bool
}

// NewClient creates a new containerd client wrapper.
func NewClient(ctx context.Context, socket, namespace string) (*Client, error) {
	inner, err := containerd.New(socket,
		containerd.WithDefaultNamespace(namespace),
		containerd.WithTimeout(5*time.Second),
	)
	if err != nil {
		return nil, fmt.Errorf("connecting to containerd at %s: %w", socket, err)
	}

	// Verify the connection works
	if _, err := inner.Version(ctx); err != nil {
		_ = inner.Close()
		return nil, fmt.Errorf("containerd health check failed: %w", err)
	}

	log.Info().
		Str("socket", socket).
		Str("namespace", namespace).
		Msg("connected to containerd")

	return &Client{
		inner:     inner,
		socket:    socket,
		namespace: namespace,
	}, nil
}

// Raw returns the underlying containerd client for direct API usage.
func (c *Client) Raw() *containerd.Client {
	return c.inner
}

// WithNamespace returns a context with the configured namespace.
func (c *Client) WithNamespace(ctx context.Context) context.Context {
	return namespaces.WithNamespace(ctx, c.namespace)
}

// Healthy checks if the containerd connection is alive.
func (c *Client) Healthy(ctx context.Context) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.closed {
		return false
	}

	_, err := c.inner.Version(ctx)
	return err == nil
}

// Reconnect attempts to re-establish the containerd connection.
func (c *Client) Reconnect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Close the old connection
	if c.inner != nil {
		_ = c.inner.Close()
	}

	inner, err := containerd.New(c.socket,
		containerd.WithDefaultNamespace(c.namespace),
		containerd.WithTimeout(5*time.Second),
	)
	if err != nil {
		return fmt.Errorf("reconnecting to containerd: %w", err)
	}

	if _, err := inner.Version(ctx); err != nil {
		_ = inner.Close()
		return fmt.Errorf("reconnect health check failed: %w", err)
	}

	c.inner = inner
	c.closed = false

	log.Info().Msg("reconnected to containerd")
	return nil
}

// Close shuts down the containerd client.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	if c.inner != nil {
		return c.inner.Close()
	}
	return nil
}

// PullImage pulls a container image if it's not already available.
func (c *Client) PullImage(ctx context.Context, ref string) (containerd.Image, error) {
	ctx = c.WithNamespace(ctx)

	// Check if image already exists
	image, err := c.inner.GetImage(ctx, ref)
	if err == nil {
		return image, nil
	}

	// Pull the image
	log.Info().Str("ref", ref).Msg("pulling image")

	image, err = c.inner.Pull(ctx, ref,
		containerd.WithPullUnpack,
	)
	if err != nil {
		return nil, fmt.Errorf("pulling image %s: %w", ref, err)
	}

	log.Info().Str("ref", ref).Msg("image pulled successfully")
	return image, nil
}
