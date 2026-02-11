package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	maxSSEStdoutBytes = 1 << 20  // 1MB
	maxSSEStderrBytes = 256 * 1024 // 256KB
)

// SSEWriter implements io.Writer and flushes each write as a Server-Sent Event.
type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	event   string // SSE event type (e.g. "stdout", "stderr")
	mu      sync.Mutex
	written atomic.Int64
	limit   int64
}

// NewSSEWriter creates an SSE writer for the given event type.
// Returns nil if the ResponseWriter does not support flushing.
func NewSSEWriter(w http.ResponseWriter, event string) *SSEWriter {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	limit := int64(maxSSEStdoutBytes)
	if event == "stderr" {
		limit = int64(maxSSEStderrBytes)
	}
	return &SSEWriter{
		w:       w,
		flusher: flusher,
		event:   event,
		limit:   limit,
	}
}

// Write sends data as an SSE event and flushes immediately.
func (s *SSEWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	// Enforce output limit (matches non-streaming caps).
	if s.written.Load() >= s.limit {
		return len(p), nil // silently drop
	}
	remaining := s.limit - s.written.Load()
	data := p
	if int64(len(data)) > remaining {
		data = data[:remaining]
	}
	s.written.Add(int64(len(data)))

	// SSE requires each line of a multi-line payload to have its own "data:" prefix.
	// Without this, a newline in user output breaks the event boundary and could
	// inject fake SSE events.
	lines := strings.Split(string(data), "\n")
	fmt.Fprintf(s.w, "event: %s\n", s.event)
	for _, line := range lines {
		fmt.Fprintf(s.w, "data: %s\n", line)
	}
	if _, err := fmt.Fprint(s.w, "\n"); err != nil {
		return 0, err
	}
	s.flusher.Flush()
	return len(p), nil
}

// sanitizeSSEData replaces newlines in data to prevent SSE event injection.
func sanitizeSSEData(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// sendSSEDone sends a completion event with the final result as JSON.
func sendSSEDone(w http.ResponseWriter, data string) {
	if flusher, ok := w.(http.Flusher); ok {
		fmt.Fprintf(w, "event: done\ndata: %s\n\n", sanitizeSSEData(data))
		flusher.Flush()
	}
}

// sendSSEError sends an error event.
func sendSSEError(w http.ResponseWriter, errMsg string) {
	if flusher, ok := w.(http.Flusher); ok {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", sanitizeSSEData(errMsg))
		flusher.Flush()
	}
}
