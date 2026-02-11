package api

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/monitor"
)

var validRequestID = regexp.MustCompile(`^[a-zA-Z0-9\-]{1,64}$`)

type contextKey string

const (
	contextKeyRequestID contextKey = "request_id"
	contextKeyAPIKey    contextKey = "api_key"
)

func RequestIDFromContext(ctx context.Context) string {
	if id, ok := ctx.Value(contextKeyRequestID).(string); ok {
		return id
	}
	return ""
}

func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" || !validRequestID.MatchString(id) {
			id = uuid.New().String()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), contextKeyRequestID, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SecurityHeadersMiddleware adds security headers to all responses.
func SecurityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func LoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		wrapped := &statusRecorder{ResponseWriter: w, status: 200}

		next.ServeHTTP(wrapped, r)

		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Int("status", wrapped.status).
			Dur("duration", time.Since(start)).
			Str("request_id", RequestIDFromContext(r.Context())).
			Str("remote_addr", r.RemoteAddr).
			Msg("request completed")
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func AuthMiddleware(allowedKeys []string, allowUnauthenticated bool) func(http.Handler) http.Handler {
	keySet := make(map[string]struct{}, len(allowedKeys))
	for _, k := range allowedKeys {
		if k == "" {
			continue
		}
		keySet[k] = struct{}{}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(keySet) == 0 {
				if allowUnauthenticated {
					next.ServeHTTP(w, r)
					return
				}
				http.Error(w, `{"error":"unauthorized","code":"AUTH_REQUIRED"}`, http.StatusUnauthorized)
				return
			}

			key := r.Header.Get("X-API-Key")
			if key == "" {
				key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			}

			if key == "" {
				http.Error(w, `{"error":"unauthorized","code":"AUTH_REQUIRED"}`, http.StatusUnauthorized)
				return
			}

			if _, ok := keySet[key]; !ok {
				http.Error(w, `{"error":"unauthorized","code":"AUTH_REQUIRED"}`, http.StatusUnauthorized)
				return
			}

			ctx := context.WithValue(r.Context(), contextKeyAPIKey, key)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

const maxRateLimitVisitors = 10000

func RateLimitMiddleware(rps float64, burst int) func(http.Handler) http.Handler {
	type visitor struct {
		tokens    float64
		lastCheck time.Time
	}

	var mu sync.Mutex
	visitors := make(map[string]*visitor)

	// Use a context so the cleanup goroutine can be stopped (e.g. in tests).
	ctx, cancel := context.WithCancel(context.Background())
	_ = cancel // caller can't reach this today, but prevents the goroutine from leaking on process exit

	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				mu.Lock()
				for ip, v := range visitors {
					if time.Since(v.lastCheck) > 5*time.Minute {
						delete(visitors, ip)
					}
				}
				mu.Unlock()
			case <-ctx.Done():
				return
			}
		}
	}()

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Strip port from RemoteAddr so each IP gets one bucket, not each TCP connection.
			ip := r.RemoteAddr
			if host, _, err := net.SplitHostPort(ip); err == nil {
				ip = host
			}

			mu.Lock()
			v, ok := visitors[ip]
			if !ok {
				// Cap the visitors map to prevent memory exhaustion from many unique IPs.
				if len(visitors) >= maxRateLimitVisitors {
					// Evict the oldest entry.
					var oldestIP string
					var oldestTime time.Time
					for k, vis := range visitors {
						if oldestIP == "" || vis.lastCheck.Before(oldestTime) {
							oldestIP = k
							oldestTime = vis.lastCheck
						}
					}
					delete(visitors, oldestIP)
				}
				v = &visitor{tokens: float64(burst), lastCheck: time.Now()}
				visitors[ip] = v
			}

			now := time.Now()
			elapsed := now.Sub(v.lastCheck).Seconds()
			v.lastCheck = now
			v.tokens += elapsed * rps
			if v.tokens > float64(burst) {
				v.tokens = float64(burst)
			}

			if v.tokens < 1 {
				mu.Unlock()
				w.Header().Set("Retry-After", "1")
				http.Error(w, `{"error":"rate limit exceeded","code":"RATE_LIMITED"}`, http.StatusTooManyRequests)
				return
			}

			v.tokens--
			mu.Unlock()

			next.ServeHTTP(w, r)
		})
	}
}

// ConcurrentClaudeMiddleware tracks concurrent claude executions and rejects
// new ones when the limit is reached. It inspects the JSON body for
// "language":"claude" without consuming it.
func ConcurrentClaudeMiddleware(maxConcurrent int) func(http.Handler) http.Handler {
	var active atomic.Int64

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only applies to execution endpoints.
			if r.URL.Path != "/execute" && r.URL.Path != "/execute/stream" {
				next.ServeHTTP(w, r)
				return
			}

			// Peek at the body to see if this is a claude request.
			body, err := io.ReadAll(r.Body)
			r.Body.Close()
			if err != nil {
				http.Error(w, `{"error":"failed to read body","code":"INVALID_REQUEST"}`, http.StatusBadRequest)
				return
			}
			// Restore the body for downstream handlers.
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Quick check: does the body contain "claude" as the language?
			var partial struct {
				Language string `json:"language"`
			}
			if json.Unmarshal(body, &partial) == nil && partial.Language == "claude" {
				// CAS loop to avoid TOCTOU between Load and Add.
				for {
					cur := active.Load()
					if cur >= int64(maxConcurrent) {
						http.Error(w, `{"error":"too many concurrent claude sessions","code":"CLAUDE_LIMIT_REACHED"}`, http.StatusTooManyRequests)
						return
					}
					if active.CompareAndSwap(cur, cur+1) {
						break
					}
				}
				defer active.Add(-1)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func MetricsMiddleware(metrics *monitor.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			metrics.RequestsInFlight.Inc()
			defer metrics.RequestsInFlight.Dec()
			next.ServeHTTP(w, r)
		})
	}
}

func RecoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Error().
					Interface("panic", rec).
					Str("path", r.URL.Path).
					Str("request_id", RequestIDFromContext(r.Context())).
					Msg("panic recovered")
				http.Error(w, `{"error":"internal server error","code":"INTERNAL"}`, http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func MaxBodyMiddleware(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
