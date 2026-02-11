package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"safe-agent-sandbox/internal/monitor"
	"safe-agent-sandbox/internal/sandbox"
)

// mockBackend implements sandbox.Backend for handler tests.
type mockBackend struct {
	result *sandbox.ExecutionResult
	err    error
}

func (m *mockBackend) Execute(_ context.Context, _ sandbox.ExecutionRequest) (*sandbox.ExecutionResult, error) {
	return m.result, m.err
}

func (m *mockBackend) ExecuteStreaming(_ context.Context, _ sandbox.ExecutionRequest, _, _ io.Writer) (*sandbox.ExecutionResult, error) {
	return m.result, m.err
}

func (m *mockBackend) Close() error { return nil }

func newTestHandlers(backend sandbox.Backend) *Handlers {
	return &Handlers{
		backend:  backend,
		metrics:  monitor.NewMetrics(),
		detector: monitor.NewEscapeDetector(),
	}
}

func postJSON(t *testing.T, handler http.HandlerFunc, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func TestHandleExecute_EscapeDetection(t *testing.T) {
	h := newTestHandlers(&mockBackend{})

	body := ExecutionRequest{
		Language: "python",
		Code:     `open("/sys/fs/cgroup/notify_on_release")`,
	}
	rec := postJSON(t, h.HandleExecute, body)

	if rec.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403", rec.Code)
	}
	var resp ErrorResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Code != "SECURITY_BLOCKED" {
		t.Errorf("got code %q, want SECURITY_BLOCKED", resp.Code)
	}
}

func TestHandleExecuteStream_EscapeDetection(t *testing.T) {
	h := newTestHandlers(&mockBackend{})

	b, _ := json.Marshal(ExecutionRequest{
		Language: "bash",
		Code:     "cat /sys/fs/cgroup/release_agent",
	})
	req := httptest.NewRequest(http.MethodPost, "/execute/stream", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleExecuteStream(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("got status %d, want 403", rec.Code)
	}
}

func TestHandleExecute_Success(t *testing.T) {
	h := newTestHandlers(&mockBackend{
		result: &sandbox.ExecutionResult{
			ID:       "test-id",
			Output:   "hello world\n",
			ExitCode: 0,
			Duration: 150 * time.Millisecond,
		},
	})

	rec := postJSON(t, h.HandleExecute, ExecutionRequest{
		Language: "python",
		Code:     "print('hello world')",
	})

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	var resp ExecutionResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != "test-id" {
		t.Errorf("ID = %q, want %q", resp.ID, "test-id")
	}
	if resp.Output != "hello world\n" {
		t.Errorf("Output = %q, want %q", resp.Output, "hello world\n")
	}
	if resp.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", resp.ExitCode)
	}
}

func TestHandleExecute_ValidationErrors(t *testing.T) {
	h := newTestHandlers(&mockBackend{})

	tests := []struct {
		name       string
		body       any
		wantStatus int
	}{
		{"empty body", map[string]string{}, http.StatusBadRequest},
		{"missing language", ExecutionRequest{Code: "x"}, http.StatusBadRequest},
		{"missing code", ExecutionRequest{Language: "python"}, http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := postJSON(t, h.HandleExecute, tt.body)
			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestHandleExecute_BackendUnavailable(t *testing.T) {
	h := newTestHandlers(nil) // nil backend

	rec := postJSON(t, h.HandleExecute, ExecutionRequest{
		Language: "python",
		Code:     "print(1)",
	})

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("got status %d, want 503", rec.Code)
	}
	var resp ErrorResponse
	json.NewDecoder(rec.Body).Decode(&resp)
	if resp.Code != "RUNNER_UNAVAILABLE" {
		t.Errorf("got code %q, want RUNNER_UNAVAILABLE", resp.Code)
	}
}
