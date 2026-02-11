package tests

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"safe-agent-sandbox/internal/monitor"
	"safe-agent-sandbox/internal/sandbox"
)

func BenchmarkExecution(b *testing.B) {
	ctx := context.Background()
	client, err := sandbox.NewClient(ctx, "/run/containerd/containerd.sock", "sandbox-bench")
	if err != nil {
		b.Skipf("containerd not available: %v", err)
	}
	defer client.Close()

	runner, err := sandbox.NewRunner(ctx, client, 100)
	if err != nil {
		b.Fatalf("failed to create runner: %v", err)
	}

	languages := []struct {
		name string
		code string
	}{
		{"python", "print('hello')"},
		{"node", "console.log('hello')"},
		{"bash", "echo hello"},
	}

	for _, lang := range languages {
		b.Run(lang.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, err := runner.Execute(ctx, sandbox.ExecutionRequest{
					Code:     lang.code,
					Language: lang.name,
					Timeout:  10 * time.Second,
					Limits:   sandbox.DefaultLimits(),
				})
				if err != nil {
					b.Fatalf("execution failed: %v", err)
				}
			}
		})
	}
}

func BenchmarkConcurrentExecutions(b *testing.B) {
	ctx := context.Background()
	client, err := sandbox.NewClient(ctx, "/run/containerd/containerd.sock", "sandbox-bench")
	if err != nil {
		b.Skipf("containerd not available: %v", err)
	}
	defer client.Close()

	runner, err := sandbox.NewRunner(ctx, client, 1000)
	if err != nil {
		b.Fatalf("failed to create runner: %v", err)
	}

	concurrencyLevels := []int{10, 50, 100, 500}

	for _, conc := range concurrencyLevels {
		b.Run(fmt.Sprintf("concurrent_%d", conc), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var wg sync.WaitGroup
				wg.Add(conc)

				for j := 0; j < conc; j++ {
					go func() {
						defer wg.Done()
						_, _ = runner.Execute(ctx, sandbox.ExecutionRequest{
							Code:     "print('hello')",
							Language: "python",
							Timeout:  10 * time.Second,
							Limits:   sandbox.DefaultLimits(),
						})
					}()
				}

				wg.Wait()
			}
		})
	}
}

func BenchmarkEscapeDetector(b *testing.B) {
	detector := monitor.NewEscapeDetector()

	codes := []struct {
		name string
		code string
	}{
		{"benign", "print('hello world')"},
		{"suspicious", "cat /proc/self/root/etc/shadow"},
		{"complex", `
import os, sys, ctypes
# Try to access host filesystem
os.system('cat /proc/self/ns/mnt')
# Try to load kernel module
ctypes.CDLL(None).init_module(0, 0, 0)
# Try metadata service
import urllib.request
urllib.request.urlopen('http://169.254.169.254/latest/meta-data/')
`},
	}

	for _, tc := range codes {
		b.Run(tc.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				detector.AnalyzeCode(tc.code)
			}
		})
	}
}

func TestStartupLatency(t *testing.T) {
	ctx := context.Background()
	client, err := sandbox.NewClient(ctx, "/run/containerd/containerd.sock", "sandbox-latency")
	if err != nil {
		t.Skipf("containerd not available: %v", err)
	}
	defer client.Close()

	runner, err := sandbox.NewRunner(ctx, client, 10)
	if err != nil {
		t.Fatalf("failed to create runner: %v", err)
	}

	// Warm up — pull images
	for _, lang := range []string{"python", "bash"} {
		_, _ = runner.Execute(ctx, sandbox.ExecutionRequest{
			Code: "echo warmup", Language: lang,
			Timeout: 30 * time.Second, Limits: sandbox.DefaultLimits(),
		})
	}

	// Measure cold-ish start (image already pulled)
	const iterations = 5
	var totalDuration time.Duration

	for range iterations {
		start := time.Now()
		result, err := runner.Execute(ctx, sandbox.ExecutionRequest{
			Code:     "echo ok",
			Language: "bash",
			Timeout:  10 * time.Second,
			Limits:   sandbox.DefaultLimits(),
		})
		elapsed := time.Since(start)
		totalDuration += elapsed

		if err != nil {
			t.Fatalf("execution failed: %v", err)
		}
		if result.ExitCode != 0 {
			t.Fatalf("non-zero exit code: %d", result.ExitCode)
		}
	}

	avgLatency := totalDuration / iterations
	t.Logf("Average execution latency: %s", avgLatency)

	// Target: <100ms for bash echo (with containerd overhead)
	// The <10ms target is for pre-warmed containers
	if avgLatency > 5*time.Second {
		t.Errorf("average latency too high: %s (target: <5s for cold start)", avgLatency)
	}
}
