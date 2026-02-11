package api

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/config"
	"safe-agent-sandbox/internal/monitor"
	"safe-agent-sandbox/internal/sandbox"
	"safe-agent-sandbox/internal/storage"
)

// Server is the main HTTP server for the sandbox API.
type Server struct {
	httpServer *http.Server
	handlers   *Handlers
	cfg        *config.Config
	startTime  time.Time
}

// NewServer creates and configures the HTTP server with all routes and middleware.
func NewServer(cfg *config.Config, backend sandbox.Backend, db *storage.DB, auditWriter *storage.AuditWriter, metrics *monitor.Metrics) *Server {
	handlers := NewHandlers(backend, db, auditWriter, metrics)

	mux := http.NewServeMux()

	// Health and metrics — no auth required
	s := &Server{
		handlers:  handlers,
		cfg:       cfg,
		startTime: time.Now(),
	}

	mux.HandleFunc("GET /health", s.handleHealth(db))
	mux.Handle("GET /metrics", promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}))

	// Execution API
	mux.HandleFunc("POST /execute", handlers.HandleExecute)
	mux.HandleFunc("POST /execute/stream", handlers.HandleExecuteStream)
	mux.HandleFunc("GET /executions", handlers.HandleListExecutions)
	mux.HandleFunc("GET /executions/{id}", handlers.HandleGetExecution)
	mux.HandleFunc("DELETE /executions/{id}", handlers.HandleKillExecution)

	// Apply middleware chain (outermost first)
	var handler http.Handler = mux
	handler = MetricsMiddleware(metrics)(handler)
	handler = AuthMiddleware(cfg.Security.AllowedKeys)(handler)
	handler = RateLimitMiddleware(cfg.Security.RateLimitRPS, cfg.Security.RateLimitBurst)(handler)
	handler = MaxBodyMiddleware(cfg.Server.MaxRequestBody)(handler)
	handler = LoggingMiddleware(handler)
	handler = RequestIDMiddleware(handler)
	handler = RecoveryMiddleware(handler)

	s.httpServer = &http.Server{
		Addr:         cfg.Address(),
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  120 * time.Second,
	}

	return s
}

// Start begins listening for requests. Uses TLS if configured.
func (s *Server) Start() error {
	if s.cfg.TLS.Enabled {
		log.Info().
			Str("addr", s.httpServer.Addr).
			Str("cert", s.cfg.TLS.CertFile).
			Msg("starting HTTPS server with TLS")

		s.httpServer.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		return s.httpServer.ListenAndServeTLS(s.cfg.TLS.CertFile, s.cfg.TLS.KeyFile)
	}

	log.Warn().Msg("TLS not enabled — running plain HTTP (not recommended for production)")
	log.Info().
		Str("addr", s.httpServer.Addr).
		Msg("starting HTTP server")
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Info().Msg("shutting down HTTP server")
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) handleHealth(db *storage.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbOK := db == nil || db.Healthy(r.Context())

		resp := HealthResponse{
			Status:     "ok",
			Database:   dbOK,
			Containerd: true, // Would check runner.client.Healthy() in practice
			Uptime:     fmt.Sprintf("%s", time.Since(s.startTime).Round(time.Second)),
		}

		if !dbOK {
			resp.Status = "degraded"
		}

		status := http.StatusOK
		if resp.Status != "ok" {
			status = http.StatusServiceUnavailable
		}

		writeJSON(w, status, resp)
	}
}
