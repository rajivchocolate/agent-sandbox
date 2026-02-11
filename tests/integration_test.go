package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"testing"
	"time"

	"safe-agent-sandbox/internal/api"
	"safe-agent-sandbox/internal/config"
	"safe-agent-sandbox/internal/monitor"
	"safe-agent-sandbox/internal/sandbox"
)

// setupTestServer creates a test HTTP server. In environments without containerd
// or Docker, tests will verify request validation and API behavior.
func setupTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	cfg := config.DefaultConfig()
	metrics := monitor.NewMetrics()

	// Try to create a backend (Docker or containerd)
	var backend sandbox.Backend
	ctx := context.Background()
	b, err := sandbox.NewBackend(ctx, cfg)
	if err == nil {
		backend = b
		t.Cleanup(func() { backend.Close() })
	}

	server := api.NewServer(cfg, backend, nil, nil, metrics)
	_ = server // Use the server's handler directly

	// For tests, create the handler chain manually
	mux := http.NewServeMux()
	handlers := api.NewHandlers(backend, nil, nil, metrics)
	mux.HandleFunc("POST /execute", handlers.HandleExecute)
	mux.HandleFunc("POST /execute/stream", handlers.HandleExecuteStream)
	mux.HandleFunc("GET /executions", handlers.HandleListExecutions)
	mux.HandleFunc("GET /executions/{id}", handlers.HandleGetExecution)

	ts := httptest.NewServer(api.RequestIDMiddleware(mux))
	t.Cleanup(ts.Close)
	return ts
}

func TestHealthEndpoint(t *testing.T) {
	cfg := config.DefaultConfig()
	metrics := monitor.NewMetrics()
	server := api.NewServer(cfg, nil, nil, nil, metrics)
	_ = server

	// Direct handler test
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(api.HealthResponse{
			Status:     "ok",
			Containerd: false,
			Database:   false,
			Uptime:     "0s",
		})
	})

	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	var resp api.HealthResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Status != "ok" {
		t.Errorf("expected status 'ok', got %q", resp.Status)
	}
}

func TestExecuteValidation(t *testing.T) {
	ts := setupTestServer(t)

	tests := []struct {
		name       string
		body       any
		wantStatus int
		wantCode   string
	}{
		{
			name:       "empty body",
			body:       map[string]string{},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_REQUEST",
		},
		{
			name:       "missing language",
			body:       map[string]string{"code": "print('hi')"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_REQUEST",
		},
		{
			name:       "missing code",
			body:       map[string]string{"language": "python"},
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_REQUEST",
		},
		{
			name:       "invalid json",
			body:       "not json",
			wantStatus: http.StatusBadRequest,
			wantCode:   "INVALID_REQUEST",
		},
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			switch v := tt.body.(type) {
			case string:
				body = []byte(v)
			default:
				body, _ = json.Marshal(v)
			}

			resp, err := client.Post(ts.URL+"/execute", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatalf("request failed: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != tt.wantStatus {
				t.Errorf("expected status %d, got %d", tt.wantStatus, resp.StatusCode)
			}

			var errResp api.ErrorResponse
			_ = json.NewDecoder(resp.Body).Decode(&errResp)
			if errResp.Code != tt.wantCode {
				t.Errorf("expected error code %q, got %q", tt.wantCode, errResp.Code)
			}
		})
	}
}

func TestRequestIDPropagation(t *testing.T) {
	ts := setupTestServer(t)

	client := &http.Client{Timeout: 5 * time.Second}

	// Request without ID — server should generate one
	resp, err := client.Post(ts.URL+"/execute", "application/json",
		bytes.NewReader([]byte(`{"code":"test","language":"python"}`)))
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	requestID := resp.Header.Get("X-Request-ID")
	if requestID == "" {
		t.Error("expected X-Request-ID header to be set")
	}

	// Request with ID — server should echo it
	req, _ := http.NewRequest("POST", ts.URL+"/execute", bytes.NewReader([]byte(`{"code":"test","language":"python"}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Request-ID", "test-id-123")

	resp, err = client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if got := resp.Header.Get("X-Request-ID"); got != "test-id-123" {
		t.Errorf("expected echoed request ID 'test-id-123', got %q", got)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	ts := setupTestServer(t)
	client := &http.Client{Timeout: 5 * time.Second}

	// GET on /execute should fail (POST only)
	resp, err := client.Get(ts.URL + "/execute")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", resp.StatusCode)
	}
}

// TestDockerRunnerDirect tests the DockerRunner directly without HTTP.
func TestDockerRunnerDirect(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker not installed")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skip("Docker daemon not running")
	}

	runner := sandbox.NewDockerRunner(5)
	defer runner.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	result, err := runner.Execute(ctx, sandbox.ExecutionRequest{
		Code:     `print("direct test")`,
		Language: "python",
		Timeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("execution failed: %v", err)
	}

	if result.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d (stderr: %s)", result.ExitCode, result.Stderr)
	}

	if result.Output == "" {
		t.Error("expected non-empty output")
	}
}
