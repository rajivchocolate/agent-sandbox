package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
)

// SSEWriter implements io.Writer and flushes each write as a Server-Sent Event.
type SSEWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
	event   string // SSE event type (e.g. "stdout", "stderr")
	mu      sync.Mutex
}

// NewSSEWriter creates an SSE writer for the given event type.
// Returns nil if the ResponseWriter does not support flushing.
func NewSSEWriter(w http.ResponseWriter, event string) *SSEWriter {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil
	}
	return &SSEWriter{
		w:       w,
		flusher: flusher,
		event:   event,
	}
}

// Write sends data as an SSE event and flushes immediately.
func (s *SSEWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(p) == 0 {
		return 0, nil
	}

	// SSE requires each line of a multi-line payload to have its own "data:" prefix.
	// Without this, a newline in user output breaks the event boundary and could
	// inject fake SSE events.
	lines := strings.Split(string(p), "\n")
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

// sendSSEDone sends a completion event with the final result as JSON.
func sendSSEDone(w http.ResponseWriter, data string) {
	if flusher, ok := w.(http.Flusher); ok {
		fmt.Fprintf(w, "event: done\ndata: %s\n\n", data)
		flusher.Flush()
	}
}

// sendSSEError sends an error event.
func sendSSEError(w http.ResponseWriter, errMsg string) {
	if flusher, ok := w.(http.Flusher); ok {
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", errMsg)
		flusher.Flush()
	}
}
