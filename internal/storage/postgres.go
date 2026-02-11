package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/rs/zerolog/log"
)

// DB wraps a PostgreSQL connection pool for audit logging.
type DB struct {
	pool *pgxpool.Pool
}

// New creates a new database connection pool.
func New(ctx context.Context, dsn string) (*DB, error) {
	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing database DSN: %w", err)
	}

	config.MaxConns = 25
	config.MinConns = 2
	config.MaxConnLifetime = 5 * time.Minute
	config.MaxConnIdleTime = 1 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("connecting to database: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}

	log.Info().Msg("connected to PostgreSQL")
	return &DB{pool: pool}, nil
}

// Close shuts down the connection pool.
func (db *DB) Close() {
	db.pool.Close()
}

// Healthy checks database connectivity.
func (db *DB) Healthy(ctx context.Context) bool {
	return db.pool.Ping(ctx) == nil
}

// LogExecution inserts an execution record into the audit log.
func (db *DB) LogExecution(ctx context.Context, exec *Execution) error {
	query := `
		INSERT INTO executions (id, language, code_hash, exit_code, output, stderr,
			duration_ms, cpu_time_ms, memory_peak_mb, security_events, status,
			request_ip, api_key_hash, created_at, completed_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

	_, err := db.pool.Exec(ctx, query,
		exec.ID, exec.Language, exec.CodeHash, exec.ExitCode,
		truncateForDB(exec.Output, 65535),
		truncateForDB(exec.Stderr, 65535),
		exec.DurationMS, exec.CPUTimeMS, exec.MemoryPeakMB,
		exec.SecurityEvents, exec.Status,
		exec.RequestIP, exec.APIKeyHash,
		exec.CreatedAt, exec.CompletedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting execution: %w", err)
	}
	return nil
}

// LogSecurityEvent inserts a security event record.
func (db *DB) LogSecurityEvent(ctx context.Context, event *SecurityEventRecord) error {
	if event.ID == "" {
		event.ID = uuid.New().String()
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now()
	}

	query := `
		INSERT INTO security_events (id, execution_id, type, severity, detail, syscall, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := db.pool.Exec(ctx, query,
		event.ID, event.ExecutionID, event.Type, event.Severity,
		event.Detail, event.Syscall, event.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("inserting security event: %w", err)
	}
	return nil
}

// GetExecution retrieves a single execution by ID.
func (db *DB) GetExecution(ctx context.Context, id string) (*Execution, error) {
	query := `
		SELECT id, language, code_hash, exit_code, output, stderr,
			duration_ms, cpu_time_ms, memory_peak_mb, security_events, status,
			request_ip, api_key_hash, created_at, completed_at
		FROM executions WHERE id = $1`

	var exec Execution
	err := db.pool.QueryRow(ctx, query, id).Scan(
		&exec.ID, &exec.Language, &exec.CodeHash, &exec.ExitCode,
		&exec.Output, &exec.Stderr,
		&exec.DurationMS, &exec.CPUTimeMS, &exec.MemoryPeakMB,
		&exec.SecurityEvents, &exec.Status,
		&exec.RequestIP, &exec.APIKeyHash,
		&exec.CreatedAt, &exec.CompletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("querying execution %s: %w", id, err)
	}
	return &exec, nil
}

// ListExecutions queries executions with optional filters.
func (db *DB) ListExecutions(ctx context.Context, filter ExecutionFilter) ([]Execution, error) {
	query := `
		SELECT id, language, code_hash, exit_code, duration_ms,
			security_events, status, created_at, completed_at
		FROM executions
		WHERE ($1 = '' OR language = $1)
		  AND ($2 = '' OR status = $2)
		ORDER BY created_at DESC
		LIMIT $3 OFFSET $4`

	limit := filter.Limit
	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	rows, err := db.pool.Query(ctx, query,
		filter.Language, filter.Status, limit, filter.Offset,
	)
	if err != nil {
		return nil, fmt.Errorf("querying executions: %w", err)
	}
	defer rows.Close()

	var results []Execution
	for rows.Next() {
		var exec Execution
		if err := rows.Scan(
			&exec.ID, &exec.Language, &exec.CodeHash, &exec.ExitCode,
			&exec.DurationMS, &exec.SecurityEvents, &exec.Status,
			&exec.CreatedAt, &exec.CompletedAt,
		); err != nil {
			return nil, fmt.Errorf("scanning execution row: %w", err)
		}
		results = append(results, exec)
	}

	return results, rows.Err()
}

func truncateForDB(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}
