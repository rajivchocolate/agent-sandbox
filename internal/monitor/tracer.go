package monitor

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

const tracerName = "safe-agent-sandbox"

// Tracer wraps OpenTelemetry tracing for the sandbox system.
type Tracer struct {
	tracer trace.Tracer
}

// NewTracer creates a new Tracer using the global TracerProvider.
func NewTracer() *Tracer {
	return &Tracer{
		tracer: otel.Tracer(tracerName),
	}
}

// StartSpan creates a new span and returns the updated context.
func (t *Tracer) StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	ctx, span := t.tracer.Start(ctx, fmt.Sprintf("sandbox.%s", name),
		trace.WithAttributes(attrs...),
	)
	return ctx, span
}

// SpanFromContext returns the current span from the context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// Common attribute keys for sandbox tracing.
var (
	AttrExecID    = attribute.Key("sandbox.execution.id")
	AttrLanguage  = attribute.Key("sandbox.language")
	AttrCodeHash  = attribute.Key("sandbox.code_hash")
	AttrExitCode  = attribute.Key("sandbox.exit_code")
	AttrDurationMS = attribute.Key("sandbox.duration_ms")
)
