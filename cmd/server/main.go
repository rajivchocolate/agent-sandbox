package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/api"
	"safe-agent-sandbox/internal/config"
	"safe-agent-sandbox/internal/monitor"
	"safe-agent-sandbox/internal/sandbox"
	"safe-agent-sandbox/internal/storage"
)

func main() {
	// Structured logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnixMs
	if os.Getenv("ENV") != "production" {
		log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})
	}

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "configs/config.yaml"
	}

	var cfg *config.Config
	var err error

	if _, statErr := os.Stat(configPath); statErr == nil {
		cfg, err = config.Load(configPath)
		if err != nil {
			log.Fatal().Err(err).Str("path", configPath).Msg("failed to load config")
		}
	} else {
		log.Info().Msg("no config file found, using defaults")
		cfg = config.DefaultConfig()
	}

	// Override port from env if set
	if port := os.Getenv("PORT"); port != "" {
		log.Info().Str("port", port).Msg("using port from environment")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initialize metrics
	metrics := monitor.NewMetrics()

	// Initialize sandbox backend (auto-detects containerd vs Docker)
	var backend sandbox.Backend
	backend, err = sandbox.NewBackend(ctx, cfg)
	if err != nil {
		log.Warn().Err(err).Msg("no sandbox backend available (execution will fail)")
		// Continue startup so health/metrics endpoints work for debugging
	}

	// Initialize database (optional — runs without it for development)
	var db *storage.DB
	if cfg.Database.DSN != "" {
		db, err = storage.New(ctx, cfg.Database.DSN)
		if err != nil {
			log.Warn().Err(err).Msg("database unavailable, audit logging disabled")
		} else {
			defer db.Close()
		}
	}

	// Initialize audit writer (buffered, reliable logging)
	var auditWriter *storage.AuditWriter
	if db != nil {
		auditWriter = storage.NewAuditWriter(db, 10000)
		auditWriter.Start()
		defer auditWriter.Flush(10 * time.Second)
	}

	// Create and start HTTP server
	server := api.NewServer(cfg, backend, db, auditWriter, metrics)

	// Graceful shutdown
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh

		log.Info().Str("signal", sig.String()).Msg("shutting down")

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.ShutdownTimeout)
		defer shutdownCancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("HTTP server shutdown error")
		}

		// Cleanup backend resources
		if backend != nil {
			if err := backend.Close(); err != nil {
				log.Error().Err(err).Msg("backend close error")
			}
		}

		cancel()
	}()

	log.Info().
		Str("addr", cfg.Address()).
		Bool("db_enabled", db != nil).
		Bool("backend_available", backend != nil).
		Msg("server starting")

	if err := server.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal().Err(err).Msg("server failed")
	}

	log.Info().Msg("server stopped")
}
