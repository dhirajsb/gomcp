package metrics

import (
	"fmt"
	"sync"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrometheusProvider implements a Prometheus metrics provider
type PrometheusProvider struct {
	name     string
	registry *prometheus.Registry

	// Metric collections
	counters   map[string]*prometheus.CounterVec
	gauges     map[string]*prometheus.GaugeVec
	histograms map[string]*prometheus.HistogramVec

	// Thread safety
	mu sync.RWMutex

	// Configuration
	config PrometheusConfig
}

// PrometheusConfig holds configuration for Prometheus metrics
type PrometheusConfig struct {
	// Namespace for all metrics (e.g., "gomcp")
	Namespace string

	// Subsystem for metrics (e.g., "server")
	Subsystem string

	// Default labels to add to all metrics
	DefaultLabels prometheus.Labels

	// HTTP handler configuration
	EnableHTTPHandler bool
	HTTPPath          string
	HTTPPort          int

	// Histogram buckets for duration metrics
	DurationBuckets []float64

	// Histogram buckets for size metrics
	SizeBuckets []float64
}

// NewPrometheus creates a new Prometheus metrics provider with default configuration
func NewPrometheus(name string) *PrometheusProvider {
	return NewPrometheusWithConfig(name, PrometheusConfig{
		Namespace:         "gomcp",
		Subsystem:         "server",
		EnableHTTPHandler: true,
		HTTPPath:          "/metrics",
		HTTPPort:          9090,
		DurationBuckets:   prometheus.DefBuckets,
		SizeBuckets:       []float64{100, 1024, 10240, 102400, 1048576, 10485760},
	})
}

// NewPrometheusWithConfig creates a new Prometheus metrics provider with custom configuration
func NewPrometheusWithConfig(name string, config PrometheusConfig) *PrometheusProvider {
	registry := prometheus.NewRegistry()

	// Add default collectors
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	return &PrometheusProvider{
		name:       name,
		registry:   registry,
		counters:   make(map[string]*prometheus.CounterVec),
		gauges:     make(map[string]*prometheus.GaugeVec),
		histograms: make(map[string]*prometheus.HistogramVec),
		config:     config,
	}
}

func (pmp *PrometheusProvider) Name() string {
	return pmp.name
}

func (pmp *PrometheusProvider) RecordCounter(name string, value int64, labels map[string]string) {
	counter := pmp.getOrCreateCounter(name, pmp.getAllLabelKeys(labels))

	// Convert labels map to prometheus Labels and add default labels
	promLabels := pmp.mergeLabels(labels)

	// Add the value to the counter
	counter.With(promLabels).Add(float64(value))
}

func (pmp *PrometheusProvider) RecordGauge(name string, value float64, labels map[string]string) {
	gauge := pmp.getOrCreateGauge(name, pmp.getAllLabelKeys(labels))

	// Convert labels map to prometheus Labels and add default labels
	promLabels := pmp.mergeLabels(labels)

	// Set the gauge value
	gauge.With(promLabels).Set(value)
}

func (pmp *PrometheusProvider) RecordHistogram(name string, value float64, labels map[string]string) {
	histogram := pmp.getOrCreateHistogram(name, pmp.getAllLabelKeys(labels))

	// Convert labels map to prometheus Labels and add default labels
	promLabels := pmp.mergeLabels(labels)

	// Observe the value in the histogram
	histogram.With(promLabels).Observe(value)
}

// getOrCreateCounter creates or retrieves a counter metric
func (pmp *PrometheusProvider) getOrCreateCounter(name string, labelNames []string) *prometheus.CounterVec {
	pmp.mu.Lock()
	defer pmp.mu.Unlock()

	if counter, exists := pmp.counters[name]; exists {
		return counter
	}

	// Create new counter
	counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: pmp.config.Namespace,
			Subsystem: pmp.config.Subsystem,
			Name:      name,
			Help:      fmt.Sprintf("Counter metric for %s", name),
		},
		labelNames,
	)

	// Register with Prometheus registry
	pmp.registry.MustRegister(counter)
	pmp.counters[name] = counter

	return counter
}

// getOrCreateGauge creates or retrieves a gauge metric
func (pmp *PrometheusProvider) getOrCreateGauge(name string, labelNames []string) *prometheus.GaugeVec {
	pmp.mu.Lock()
	defer pmp.mu.Unlock()

	if gauge, exists := pmp.gauges[name]; exists {
		return gauge
	}

	// Create new gauge
	gauge := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: pmp.config.Namespace,
			Subsystem: pmp.config.Subsystem,
			Name:      name,
			Help:      fmt.Sprintf("Gauge metric for %s", name),
		},
		labelNames,
	)

	// Register with Prometheus registry
	pmp.registry.MustRegister(gauge)
	pmp.gauges[name] = gauge

	return gauge
}

// getOrCreateHistogram creates or retrieves a histogram metric
func (pmp *PrometheusProvider) getOrCreateHistogram(name string, labelNames []string) *prometheus.HistogramVec {
	pmp.mu.Lock()
	defer pmp.mu.Unlock()

	if histogram, exists := pmp.histograms[name]; exists {
		return histogram
	}

	// Determine which buckets to use based on metric name
	buckets := pmp.getBucketsForMetric(name)

	// Create new histogram
	histogram := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: pmp.config.Namespace,
			Subsystem: pmp.config.Subsystem,
			Name:      name,
			Help:      fmt.Sprintf("Histogram metric for %s", name),
			Buckets:   buckets,
		},
		labelNames,
	)

	// Register with Prometheus registry
	pmp.registry.MustRegister(histogram)
	pmp.histograms[name] = histogram

	return histogram
}

// getBucketsForMetric returns appropriate histogram buckets based on metric name
func (pmp *PrometheusProvider) getBucketsForMetric(name string) []float64 {
	// Use duration buckets for time-related metrics
	if containsAny(name, []string{"duration", "latency", "time", "delay"}) {
		return pmp.config.DurationBuckets
	}

	// Use size buckets for size-related metrics
	if containsAny(name, []string{"size", "bytes", "length", "count"}) {
		return pmp.config.SizeBuckets
	}

	// Default buckets
	return prometheus.DefBuckets
}

// mergeLabels merges user labels with default labels
func (pmp *PrometheusProvider) mergeLabels(userLabels map[string]string) prometheus.Labels {
	merged := make(prometheus.Labels)

	// Add default labels first
	for k, v := range pmp.config.DefaultLabels {
		merged[k] = v
	}

	// Add user labels (override defaults if same key)
	for k, v := range userLabels {
		merged[k] = v
	}

	return merged
}

// StartHTTPServer starts the Prometheus HTTP metrics server
func (pmp *PrometheusProvider) StartHTTPServer() error {
	if !pmp.config.EnableHTTPHandler {
		return nil
	}

	// Create HTTP handler
	handler := promhttp.HandlerFor(pmp.registry, promhttp.HandlerOpts{
		Registry:          pmp.registry,
		EnableOpenMetrics: true,
	})

	// Set up HTTP server
	mux := http.NewServeMux()
	mux.Handle(pmp.config.HTTPPath, handler)

	// Start server in background
	go func() {
		addr := fmt.Sprintf(":%d", pmp.config.HTTPPort)
		if err := http.ListenAndServe(addr, mux); err != nil {
			// Log error but don't crash the application
			fmt.Printf("Prometheus HTTP server error: %v\n", err)
		}
	}()

	return nil
}

// GetHTTPHandler returns the Prometheus HTTP handler for embedding in existing servers
func (pmp *PrometheusProvider) GetHTTPHandler() http.Handler {
	return promhttp.HandlerFor(pmp.registry, promhttp.HandlerOpts{
		Registry:          pmp.registry,
		EnableOpenMetrics: true,
	})
}

// GetRegistry returns the underlying Prometheus registry
func (pmp *PrometheusProvider) GetRegistry() *prometheus.Registry {
	return pmp.registry
}

func (pmp *PrometheusProvider) Close() error {
	// Prometheus metrics don't need explicit cleanup
	// Registry will be garbage collected
	return nil
}

// Predefined metric methods for common use cases

// RecordRequestDuration records HTTP request duration
func (pmp *PrometheusProvider) RecordRequestDuration(method, path, status string, duration float64) {
	pmp.RecordHistogram("request_duration_seconds", duration, map[string]string{
		"method": method,
		"path":   path,
		"status": status,
	})
}

// RecordRequestCount increments HTTP request count
func (pmp *PrometheusProvider) RecordRequestCount(method, path, status string) {
	pmp.RecordCounter("requests_total", 1, map[string]string{
		"method": method,
		"path":   path,
		"status": status,
	})
}

// RecordActiveConnections sets the number of active connections
func (pmp *PrometheusProvider) RecordActiveConnections(transport string, count float64) {
	pmp.RecordGauge("active_connections", count, map[string]string{
		"transport": transport,
	})
}

// RecordCacheOperation records cache hit/miss statistics
func (pmp *PrometheusProvider) RecordCacheOperation(cache, operation string, hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}

	pmp.RecordCounter("cache_operations_total", 1, map[string]string{
		"cache":     cache,
		"operation": operation,
		"result":    result,
	})
}

// RecordAuthOperation records authentication events
func (pmp *PrometheusProvider) RecordAuthOperation(provider, result string) {
	pmp.RecordCounter("auth_operations_total", 1, map[string]string{
		"provider": provider,
		"result":   result,
	})
}

// RecordToolExecution records MCP tool execution metrics
func (pmp *PrometheusProvider) RecordToolExecution(tool, status string, duration float64) {
	pmp.RecordCounter("tool_executions_total", 1, map[string]string{
		"tool":   tool,
		"status": status,
	})

	pmp.RecordHistogram("tool_execution_duration_seconds", duration, map[string]string{
		"tool":   tool,
		"status": status,
	})
}

// Helper functions

// getLabelsKeys extracts keys from labels map
func getLabelsKeys(labels map[string]string) []string {
	if labels == nil {
		return []string{}
	}

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	return keys
}

// getAllLabelKeys extracts keys from both default labels and user labels
func (pmp *PrometheusProvider) getAllLabelKeys(userLabels map[string]string) []string {
	// Use a map to ensure unique keys
	keyMap := make(map[string]bool)

	// Add default label keys
	for k := range pmp.config.DefaultLabels {
		keyMap[k] = true
	}

	// Add user label keys
	for k := range userLabels {
		keyMap[k] = true
	}

	// Convert to slice
	keys := make([]string, 0, len(keyMap))
	for k := range keyMap {
		keys = append(keys, k)
	}

	return keys
}

// containsAny checks if string contains any of the substrings
func containsAny(s string, substrs []string) bool {
	for _, substr := range substrs {
		if len(s) >= len(substr) {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
		}
	}
	return false
}
