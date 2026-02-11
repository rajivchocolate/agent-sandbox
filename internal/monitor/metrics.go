package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds all Prometheus metrics for the sandbox system.
type Metrics struct {
	Registry *prometheus.Registry

	ExecutionsTotal    *prometheus.CounterVec
	ExecutionDuration  *prometheus.HistogramVec
	ExecutionErrors    *prometheus.CounterVec
	ActiveExecutions   prometheus.Gauge
	SecurityEvents     *prometheus.CounterVec
	ContainerPoolSize  *prometheus.GaugeVec
	ContainerdLatency  *prometheus.HistogramVec
	RequestsInFlight   prometheus.Gauge
	CodeSizeBytes      prometheus.Histogram
	OutputSizeBytes    prometheus.Histogram
}

// NewMetrics creates and registers all Prometheus metrics using a dedicated registry.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		Registry: reg,

		ExecutionsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sandbox",
				Name:      "executions_total",
				Help:      "Total number of sandbox executions by language and status.",
			},
			[]string{"language", "status"},
		),

		ExecutionDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sandbox",
				Name:      "execution_duration_seconds",
				Help:      "Duration of sandbox executions in seconds.",
				Buckets:   []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
			},
			[]string{"language"},
		),

		ExecutionErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sandbox",
				Name:      "execution_errors_total",
				Help:      "Total sandbox execution errors by type.",
			},
			[]string{"type"},
		),

		ActiveExecutions: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sandbox",
				Name:      "active_executions",
				Help:      "Number of currently running sandbox executions.",
			},
		),

		SecurityEvents: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sandbox",
				Name:      "security_events_total",
				Help:      "Total security events detected during execution.",
			},
			[]string{"type"},
		),

		ContainerPoolSize: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: "sandbox",
				Name:      "container_pool_size",
				Help:      "Number of pre-warmed containers in the pool.",
			},
			[]string{"runtime"},
		),

		ContainerdLatency: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sandbox",
				Name:      "containerd_operation_duration_seconds",
				Help:      "Duration of containerd API operations.",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1},
			},
			[]string{"operation"},
		),

		RequestsInFlight: prometheus.NewGauge(
			prometheus.GaugeOpts{
				Namespace: "sandbox",
				Subsystem: "api",
				Name:      "requests_in_flight",
				Help:      "Number of HTTP requests currently being processed.",
			},
		),

		CodeSizeBytes: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "sandbox",
				Name:      "code_size_bytes",
				Help:      "Size of submitted code in bytes.",
				Buckets:   prometheus.ExponentialBuckets(100, 4, 8),
			},
		),

		OutputSizeBytes: prometheus.NewHistogram(
			prometheus.HistogramOpts{
				Namespace: "sandbox",
				Name:      "output_size_bytes",
				Help:      "Size of execution output in bytes.",
				Buckets:   prometheus.ExponentialBuckets(10, 4, 8),
			},
		),
	}

	// Register all collectors
	reg.MustRegister(
		m.ExecutionsTotal,
		m.ExecutionDuration,
		m.ExecutionErrors,
		m.ActiveExecutions,
		m.SecurityEvents,
		m.ContainerPoolSize,
		m.ContainerdLatency,
		m.RequestsInFlight,
		m.CodeSizeBytes,
		m.OutputSizeBytes,
	)

	return m
}

// RecordExecution records metrics for a completed execution.
func (m *Metrics) RecordExecution(language, status string, durationSec float64) {
	m.ExecutionsTotal.WithLabelValues(language, status).Inc()
	m.ExecutionDuration.WithLabelValues(language).Observe(durationSec)
}

// RecordError records an execution error by type.
func (m *Metrics) RecordError(errType string) {
	m.ExecutionErrors.WithLabelValues(errType).Inc()
}

// RecordSecurityEvent records a security event.
func (m *Metrics) RecordSecurityEvent(eventType string) {
	m.SecurityEvents.WithLabelValues(eventType).Inc()
}
