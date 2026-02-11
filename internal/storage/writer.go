package storage

import (
	"context"
	"math"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

type AuditWriter struct {
	db   *DB
	ch   chan *Execution
	wg   sync.WaitGroup
	done chan struct{}
}

func NewAuditWriter(db *DB, bufferSize int) *AuditWriter {
	if bufferSize < 1 {
		bufferSize = 10000
	}
	return &AuditWriter{
		db:   db,
		ch:   make(chan *Execution, bufferSize),
		done: make(chan struct{}),
	}
}

func (w *AuditWriter) Start() {
	w.wg.Add(1)
	go w.processLoop()
}

func (w *AuditWriter) Log(exec *Execution) {
	select {
	case w.ch <- exec:
	default:
		log.Warn().Str("exec_id", exec.ID).Msg("audit buffer full, dropping log entry")
	}
}

func (w *AuditWriter) Flush(timeout time.Duration) {
	close(w.done)

	doneCh := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(doneCh)
	}()

	select {
	case <-doneCh:
		log.Info().Msg("audit writer flushed")
	case <-time.After(timeout):
		log.Warn().Msg("audit writer flush timed out")
	}
}

func (w *AuditWriter) processLoop() {
	defer w.wg.Done()

	for {
		select {
		case exec := <-w.ch:
			w.writeWithRetry(exec)
		case <-w.done:
			// Drain remaining entries
			for {
				select {
				case exec := <-w.ch:
					w.writeWithRetry(exec)
				default:
					return
				}
			}
		}
	}
}

func (w *AuditWriter) writeWithRetry(exec *Execution) {
	const maxRetries = 3

	for attempt := 0; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := w.db.LogExecution(ctx, exec)
		cancel()

		if err == nil {
			return
		}

		if attempt < maxRetries {
			backoff := time.Duration(math.Pow(2, float64(attempt))) * 100 * time.Millisecond
			log.Warn().
				Err(err).
				Str("exec_id", exec.ID).
				Int("attempt", attempt+1).
				Dur("backoff", backoff).
				Msg("audit write failed, retrying")
			time.Sleep(backoff)
		} else {
			log.Error().
				Err(err).
				Str("exec_id", exec.ID).
				Msg("audit write failed permanently after retries")
		}
	}
}
