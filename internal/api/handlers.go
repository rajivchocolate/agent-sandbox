package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"safe-agent-sandbox/internal/monitor"
	"safe-agent-sandbox/internal/sandbox"
	"safe-agent-sandbox/internal/storage"
)

type Handlers struct {
	backend      sandbox.Backend
	db           *storage.DB
	auditWriter  *storage.AuditWriter
	metrics      *monitor.Metrics
	detector     *monitor.EscapeDetector
}

func NewHandlers(backend sandbox.Backend, db *storage.DB, auditWriter *storage.AuditWriter, metrics *monitor.Metrics) *Handlers {
	return &Handlers{
		backend:     backend,
		db:          db,
		auditWriter: auditWriter,
		metrics:     metrics,
		detector:    monitor.NewEscapeDetector(),
	}
}

func (h *Handlers) HandleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, r)
		return
	}

	var req ExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON: "+err.Error(), "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}

	if req.Language == "" {
		writeError(w, "language is required", "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}
	if req.Code == "" {
		writeError(w, "code is required", "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}

	h.metrics.CodeSizeBytes.Observe(float64(len(req.Code)))

	detections := h.detector.AnalyzeCode(req.Code)
	for _, d := range detections {
		h.metrics.RecordSecurityEvent(d.Pattern)
	}

	timeout := 10 * time.Second
	if req.Timeout.Duration > 0 {
		timeout = req.Timeout.Duration
	}

	limits := sandbox.DefaultLimits()
	if req.Limits.MemoryMB > 0 {
		limits = sandbox.ResourceLimits{
			CPUShares: req.Limits.CPUShares,
			MemoryMB:  req.Limits.MemoryMB,
			PidsLimit: req.Limits.PidsLimit,
			DiskMB:    req.Limits.DiskMB,
		}
	}

	execReq := sandbox.ExecutionRequest{
		Code:           req.Code,
		Language:       req.Language,
		Timeout:        timeout,
		Limits:         limits,
		NetworkEnabled: req.Perms.Network.Enabled,
	}

	if h.backend == nil {
		writeError(w, "sandbox backend unavailable", "RUNNER_UNAVAILABLE", http.StatusServiceUnavailable, r)
		return
	}

	h.metrics.ActiveExecutions.Inc()
	defer h.metrics.ActiveExecutions.Dec()

	start := time.Now()

	result, err := h.backend.Execute(r.Context(), execReq)
	duration := time.Since(start)

	status := "success"
	if err != nil {
		switch {
		case errors.Is(err, sandbox.ErrTimeout):
			status = "timeout"
		case errors.Is(err, sandbox.ErrOOM):
			status = "oom"
		case errors.Is(err, sandbox.ErrSecurityViolation):
			status = "security"
		case errors.Is(err, sandbox.ErrInvalidRequest), errors.Is(err, sandbox.ErrUnsupportedLang):
			status = "validation"
			writeError(w, err.Error(), "VALIDATION_ERROR", http.StatusBadRequest, r)
			h.metrics.RecordExecution(req.Language, status, duration.Seconds())
			return
		default:
			status = "error"
		}
	}

	h.metrics.RecordExecution(req.Language, status, duration.Seconds())

	if result == nil && err != nil {
		h.metrics.RecordError("internal")
		log.Error().Err(err).Str("request_id", RequestIDFromContext(r.Context())).Msg("execution failed")
		writeError(w, "execution failed", "EXECUTION_FAILED", http.StatusInternalServerError, r)
		return
	}

	if result != nil {
		outputDetections := h.detector.AnalyzeOutput(result.Output)
		for _, d := range outputDetections {
			h.metrics.RecordSecurityEvent(d.Pattern)
			result.SecurityEvents = append(result.SecurityEvents, sandbox.SecurityEvent{
				Type:   d.Pattern,
				Detail: d.Detail,
			})
		}
	}

	apiSecEvents := make([]SecurityEvent, 0, len(result.SecurityEvents))
	for _, e := range result.SecurityEvents {
		apiSecEvents = append(apiSecEvents, SecurityEvent{
			Type:    e.Type,
			Syscall: e.Syscall,
			Detail:  e.Detail,
		})
	}

	resp := ExecutionResponse{
		ID:       result.ID,
		Output:   result.Output,
		Stderr:   result.Stderr,
		ExitCode: result.ExitCode,
		Duration: result.Duration.String(),
		ResourceUsage: ResourceUsage{
			CPUTimeMS:    result.ResourceUsage.CPUTimeMS,
			MemoryPeakMB: result.ResourceUsage.MemoryPeakMB,
			PidsUsed:     result.ResourceUsage.PidsUsed,
		},
		SecurityEvents: apiSecEvents,
	}

	h.metrics.OutputSizeBytes.Observe(float64(len(result.Output) + len(result.Stderr)))

	h.logAudit(result, req.Language, status, start, r)

	writeJSON(w, http.StatusOK, resp)
}

func (h *Handlers) HandleExecuteStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, r)
		return
	}

	var req ExecutionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON: "+err.Error(), "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}

	if req.Language == "" || req.Code == "" {
		writeError(w, "language and code are required", "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}

	if h.backend == nil {
		writeError(w, "sandbox backend unavailable", "RUNNER_UNAVAILABLE", http.StatusServiceUnavailable, r)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	stdoutWriter := NewSSEWriter(w, "stdout")
	stderrWriter := NewSSEWriter(w, "stderr")
	if stdoutWriter == nil || stderrWriter == nil {
		writeError(w, "streaming not supported", "STREAMING_UNSUPPORTED", http.StatusInternalServerError, r)
		return
	}

	timeout := 10 * time.Second
	if req.Timeout.Duration > 0 {
		timeout = req.Timeout.Duration
	}

	limits := sandbox.DefaultLimits()
	if req.Limits.MemoryMB > 0 {
		limits = sandbox.ResourceLimits{
			CPUShares: req.Limits.CPUShares,
			MemoryMB:  req.Limits.MemoryMB,
			PidsLimit: req.Limits.PidsLimit,
			DiskMB:    req.Limits.DiskMB,
		}
	}

	execReq := sandbox.ExecutionRequest{
		Code:           req.Code,
		Language:       req.Language,
		Timeout:        timeout,
		Limits:         limits,
		NetworkEnabled: req.Perms.Network.Enabled,
	}

	h.metrics.ActiveExecutions.Inc()
	defer h.metrics.ActiveExecutions.Dec()

	start := time.Now()
	result, err := h.backend.ExecuteStreaming(r.Context(), execReq, stdoutWriter, stderrWriter)

	if err != nil && result == nil {
		log.Error().Err(err).Str("request_id", RequestIDFromContext(r.Context())).Msg("streaming execution failed")
		sendSSEError(w, "execution failed")
		return
	}

	if result != nil {
		doneData, _ := json.Marshal(map[string]any{
			"id":        result.ID,
			"exit_code": result.ExitCode,
			"duration":  result.Duration.String(),
		})
		sendSSEDone(w, string(doneData))

		status := "success"
		if err != nil {
			status = "error"
		}
		h.logAudit(result, req.Language, status, start, r)
	}
}

func (h *Handlers) HandleGetExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, r)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, "execution ID required", "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}

	if h.db == nil {
		writeError(w, "database not configured", "DB_UNAVAILABLE", http.StatusServiceUnavailable, r)
		return
	}

	exec, err := h.db.GetExecution(r.Context(), id)
	if err != nil {
		writeError(w, "execution not found", "NOT_FOUND", http.StatusNotFound, r)
		return
	}

	writeJSON(w, http.StatusOK, exec)
}

func (h *Handlers) HandleListExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, r)
		return
	}

	if h.db == nil {
		writeError(w, "database not configured", "DB_UNAVAILABLE", http.StatusServiceUnavailable, r)
		return
	}

	filter := storage.ExecutionFilter{
		Language: r.URL.Query().Get("language"),
		Status:   r.URL.Query().Get("status"),
		Limit:    100,
	}

	execs, err := h.db.ListExecutions(r.Context(), filter)
	if err != nil {
		writeError(w, "query failed", "INTERNAL", http.StatusInternalServerError, r)
		return
	}

	writeJSON(w, http.StatusOK, execs)
}

func (h *Handlers) HandleKillExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		writeError(w, "method not allowed", "METHOD_NOT_ALLOWED", http.StatusMethodNotAllowed, r)
		return
	}

	id := r.PathValue("id")
	if id == "" {
		writeError(w, "execution ID required", "INVALID_REQUEST", http.StatusBadRequest, r)
		return
	}

	// In a full implementation, we'd track active tasks by ID and kill them
	log.Info().Str("exec_id", id).Msg("kill requested for execution")
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "kill_requested", "id": id})
}

func (h *Handlers) logAudit(result *sandbox.ExecutionResult, language, status string, start time.Time, r *http.Request) {
	if h.auditWriter == nil {
		return
	}

	completedAt := time.Now()
	h.auditWriter.Log(&storage.Execution{
		ID:             result.ID,
		Language:       language,
		CodeHash:       result.CodeHash,
		ExitCode:       result.ExitCode,
		Output:         result.Output,
		Stderr:         result.Stderr,
		DurationMS:     result.Duration.Milliseconds(),
		SecurityEvents: len(result.SecurityEvents),
		Status:         status,
		RequestIP:      r.RemoteAddr,
		CreatedAt:      start,
		CompletedAt:    &completedAt,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Error().Err(err).Msg("failed to encode response")
	}
}

func writeError(w http.ResponseWriter, msg, code string, status int, r *http.Request) {
	resp := ErrorResponse{
		Error:     msg,
		Code:      code,
		RequestID: RequestIDFromContext(r.Context()),
	}
	writeJSON(w, status, resp)
}
