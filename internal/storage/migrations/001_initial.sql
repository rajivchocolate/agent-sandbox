-- 001_initial.sql
-- Initial schema for safe-agent-sandbox audit log

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS executions (
    id              TEXT PRIMARY KEY,
    language        TEXT NOT NULL,
    code_hash       TEXT NOT NULL,
    exit_code       INTEGER NOT NULL DEFAULT -1,
    output          TEXT NOT NULL DEFAULT '',
    stderr          TEXT NOT NULL DEFAULT '',
    duration_ms     BIGINT NOT NULL DEFAULT 0,
    cpu_time_ms     BIGINT NOT NULL DEFAULT 0,
    memory_peak_mb  BIGINT NOT NULL DEFAULT 0,
    security_events INTEGER NOT NULL DEFAULT 0,
    status          TEXT NOT NULL DEFAULT 'running',
    request_ip      TEXT NOT NULL DEFAULT '',
    api_key_hash    TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at    TIMESTAMPTZ
);

-- Index for listing recent executions
CREATE INDEX idx_executions_created_at ON executions (created_at DESC);

-- Index for filtering by status
CREATE INDEX idx_executions_status ON executions (status);

-- Index for filtering by language
CREATE INDEX idx_executions_language ON executions (language);

-- Index for code hash lookups (caching)
CREATE INDEX idx_executions_code_hash ON executions (code_hash);

CREATE TABLE IF NOT EXISTS security_events (
    id              TEXT PRIMARY KEY,
    execution_id    TEXT NOT NULL REFERENCES executions(id) ON DELETE CASCADE,
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL,
    detail          TEXT NOT NULL DEFAULT '',
    syscall         TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for querying security events by execution
CREATE INDEX idx_security_events_execution ON security_events (execution_id);

-- Index for querying by severity
CREATE INDEX idx_security_events_severity ON security_events (severity);

-- Index for time-range queries on security events
CREATE INDEX idx_security_events_created_at ON security_events (created_at DESC);
