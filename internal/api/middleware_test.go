package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAuthMiddleware_EmptyKeysRejectsRequests(t *testing.T) {
	handler := AuthMiddleware(nil, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/execute", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401", rec.Code)
	}
}

func TestAuthMiddleware_ExplicitAllowUnauthenticated(t *testing.T) {
	handler := AuthMiddleware(nil, true)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/execute", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", rec.Code)
	}
}

func TestAuthMiddleware_ValidKey(t *testing.T) {
	handler := AuthMiddleware([]string{"good-key"}, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/execute", nil)
	req.Header.Set("X-API-Key", "good-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200", rec.Code)
	}
}

func TestAuthMiddleware_InvalidKey(t *testing.T) {
	handler := AuthMiddleware([]string{"good-key"}, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/execute", nil)
	req.Header.Set("X-API-Key", "bad-key")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got status %d, want 401", rec.Code)
	}
}

func TestConcurrentClaudeMiddleware_RejectsOverLimit(t *testing.T) {
	// Middleware with max 1 concurrent claude session.
	mw := ConcurrentClaudeMiddleware(1)

	blocked := make(chan struct{})
	unblock := make(chan struct{})

	// Inner handler that blocks until we signal.
	inner := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case blocked <- struct{}{}:
		default:
		}
		<-unblock
		w.WriteHeader(http.StatusOK)
	}))

	// Start first claude request (will block in handler).
	go func() {
		body, _ := json.Marshal(map[string]string{"language": "claude", "code": "hi"})
		req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		inner.ServeHTTP(rec, req)
	}()

	// Wait for first request to enter handler.
	<-blocked

	// Second claude request should be rejected.
	body, _ := json.Marshal(map[string]string{"language": "claude", "code": "hi"})
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	inner.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("got status %d, want 429", rec.Code)
	}

	// Unblock the first request.
	close(unblock)
}

func TestConcurrentClaudeMiddleware_AllowsPython(t *testing.T) {
	mw := ConcurrentClaudeMiddleware(0) // 0 means all claude blocked

	inner := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	body, _ := json.Marshal(map[string]string{"language": "python", "code": "print(1)"})
	req := httptest.NewRequest(http.MethodPost, "/execute", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	inner.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("got status %d, want 200 (python should not be limited)", rec.Code)
	}
}
