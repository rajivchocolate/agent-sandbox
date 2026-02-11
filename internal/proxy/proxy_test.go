package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"testing"
)

func TestAuthProxy_SecretValidation(t *testing.T) {
	// Fake upstream that always returns 200.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)
	rp := httputil.NewSingleHostReverseProxy(target)

	tests := []struct {
		name       string
		secret     string // AuthProxy shared secret ("" = no secret required)
		presented  string // x-api-key the caller sends
		wantStatus int
	}{
		{"valid secret", "my-secret", "my-secret", http.StatusOK},
		{"wrong secret", "my-secret", "wrong", http.StatusForbidden},
		{"empty presented", "my-secret", "", http.StatusForbidden},
		{"no secret configured (pass-through)", "", "", http.StatusOK},
		{"no secret configured with random key", "", "anything", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ap := &AuthProxy{token: "real-token", secret: tt.secret}
			handler := ap.handleProxy(rp)

			req := httptest.NewRequest(http.MethodGet, "/v1/messages", nil)
			if tt.presented != "" {
				req.Header.Set("x-api-key", tt.presented)
			}
			rec := httptest.NewRecorder()
			handler(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("got status %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

func TestAuthProxy_HeaderInjection(t *testing.T) {
	var gotHeaders http.Header
	var gotHost string

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		gotHost = r.Host
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	target, _ := url.Parse(upstream.URL)

	ap := &AuthProxy{token: "real-token-abc", secret: ""}

	// Replicate the Director logic from New() but pointed at our fake upstream.
	rp := httputil.NewSingleHostReverseProxy(target)
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		origDirector(r)
		r.Header.Del("x-api-key")
		r.Header.Del("Authorization")
		r.Header.Set("x-api-key", ap.token)
		r.Host = anthropicHost
	}

	handler := ap.handleProxy(rp)

	req := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	req.Header.Set("x-api-key", "caller-junk")
	req.Header.Set("Authorization", "Bearer caller-junk")
	rec := httptest.NewRecorder()

	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("got status %d, want 200", rec.Code)
	}
	if got := gotHeaders.Get("x-api-key"); got != "real-token-abc" {
		t.Errorf("x-api-key = %q, want %q", got, "real-token-abc")
	}
	if gotHeaders.Get("Authorization") != "" {
		t.Errorf("Authorization header should be stripped, got %q", gotHeaders.Get("Authorization"))
	}
	if gotHost != anthropicHost {
		t.Errorf("Host = %q, want %q", gotHost, anthropicHost)
	}
}

func TestAuthProxy_StartAndClose(t *testing.T) {
	// Find a free port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	ap := New(port, "tok", "sec")
	if err := ap.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Verify the proxy is listening.
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	resp.Body.Close()
	// Without the correct secret we expect 403.
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("got status %d, want 403", resp.StatusCode)
	}

	// Shutdown.
	if err := ap.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Verify stopped — connection should be refused.
	_, err = http.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err == nil {
		t.Error("expected connection error after Close, got nil")
	}
}
