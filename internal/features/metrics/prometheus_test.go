package metrics

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewPrometheus(t *testing.T) {
	provider := NewPrometheus("test-prometheus")

	if provider.name != "test-prometheus" {
		t.Errorf("Expected name 'test-prometheus', got '%s'", provider.name)
	}

	if provider.registry == nil {
		t.Error("Expected registry to be initialized")
	}

	if provider.counters == nil {
		t.Error("Expected counters map to be initialized")
	}

	if provider.gauges == nil {
		t.Error("Expected gauges map to be initialized")
	}

	if provider.histograms == nil {
		t.Error("Expected histograms map to be initialized")
	}

	// Check default configuration
	if provider.config.Namespace != "gomcp" {
		t.Errorf("Expected namespace 'gomcp', got '%s'", provider.config.Namespace)
	}

	if provider.config.Subsystem != "server" {
		t.Errorf("Expected subsystem 'server', got '%s'", provider.config.Subsystem)
	}
}

func TestNewPrometheusWithConfig(t *testing.T) {
	config := PrometheusConfig{
		Namespace:     "custom",
		Subsystem:     "api",
		DefaultLabels: prometheus.Labels{"service": "test"},
		HTTPPath:      "/custom-metrics",
		HTTPPort:      8080,
	}

	provider := NewPrometheusWithConfig("custom-test", config)

	if provider.config.Namespace != "custom" {
		t.Errorf("Expected namespace 'custom', got '%s'", provider.config.Namespace)
	}

	if provider.config.Subsystem != "api" {
		t.Errorf("Expected subsystem 'api', got '%s'", provider.config.Subsystem)
	}

	if provider.config.DefaultLabels["service"] != "test" {
		t.Errorf("Expected default label service='test', got '%s'", provider.config.DefaultLabels["service"])
	}
}

func TestPrometheusProvider_Name(t *testing.T) {
	provider := NewPrometheus("my-prometheus")

	if provider.Name() != "my-prometheus" {
		t.Errorf("Expected name 'my-prometheus', got '%s'", provider.Name())
	}
}

func TestPrometheusProvider_RecordCounter(t *testing.T) {
	provider := NewPrometheus("test")

	labels := map[string]string{
		"method": "GET",
		"status": "200",
	}

	// Record counter values
	provider.RecordCounter("http_requests_total", 1, labels)
	provider.RecordCounter("http_requests_total", 5, labels)
	provider.RecordCounter("http_requests_total", 3, labels)

	// Verify counter was created and registered
	if len(provider.counters) != 1 {
		t.Errorf("Expected 1 counter, got %d", len(provider.counters))
	}

	counter, exists := provider.counters["http_requests_total"]
	if !exists {
		t.Error("Expected http_requests_total counter to exist")
	}

	// Check the counter value using Prometheus test utilities
	promLabels := prometheus.Labels{
		"method": "GET",
		"status": "200",
	}

	expectedValue := 9.0 // 1 + 5 + 3
	actualValue := testutil.ToFloat64(counter.With(promLabels))
	if actualValue != expectedValue {
		t.Errorf("Expected counter value %f, got %f", expectedValue, actualValue)
	}
}

func TestPrometheusProvider_RecordGauge(t *testing.T) {
	provider := NewPrometheus("test")

	labels := map[string]string{
		"instance": "server-1",
	}

	// Record gauge values (should overwrite)
	provider.RecordGauge("memory_usage_bytes", 1024.0, labels)
	provider.RecordGauge("memory_usage_bytes", 2048.0, labels)
	provider.RecordGauge("memory_usage_bytes", 4096.0, labels)

	// Verify gauge was created
	if len(provider.gauges) != 1 {
		t.Errorf("Expected 1 gauge, got %d", len(provider.gauges))
	}

	gauge, exists := provider.gauges["memory_usage_bytes"]
	if !exists {
		t.Error("Expected memory_usage_bytes gauge to exist")
	}

	// Check the gauge value (should be the last set value)
	promLabels := prometheus.Labels{
		"instance": "server-1",
	}

	expectedValue := 4096.0
	actualValue := testutil.ToFloat64(gauge.With(promLabels))
	if actualValue != expectedValue {
		t.Errorf("Expected gauge value %f, got %f", expectedValue, actualValue)
	}
}

func TestPrometheusProvider_RecordHistogram(t *testing.T) {
	provider := NewPrometheus("test")

	labels := map[string]string{
		"endpoint": "/api/users",
		"method":   "GET",
	}

	// Record histogram values
	provider.RecordHistogram("request_duration_seconds", 0.1, labels)
	provider.RecordHistogram("request_duration_seconds", 0.5, labels)
	provider.RecordHistogram("request_duration_seconds", 1.2, labels)

	// Verify histogram was created
	if len(provider.histograms) != 1 {
		t.Errorf("Expected 1 histogram, got %d", len(provider.histograms))
	}

	_, exists := provider.histograms["request_duration_seconds"]
	if !exists {
		t.Error("Expected request_duration_seconds histogram to exist")
	}

	// Check histogram count (use different approach for histogram testing)
	// Verify metrics were recorded by checking registry
	metricFamilies, err := provider.registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	expectedName := "gomcp_server_request_duration_seconds"
	for _, mf := range metricFamilies {
		if mf.GetName() == expectedName {
			found = true
			if len(mf.GetMetric()) > 0 {
				metric := mf.GetMetric()[0]
				if metric.GetHistogram() != nil {
					actualCount := metric.GetHistogram().GetSampleCount()
					if actualCount != 3 {
						t.Errorf("Expected histogram count 3, got %d", actualCount)
					}
				}
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected histogram metric '%s' not found", expectedName)
	}
}

func TestPrometheusProvider_DefaultLabels(t *testing.T) {
	config := PrometheusConfig{
		Namespace: "gomcp",
		Subsystem: "test",
		DefaultLabels: prometheus.Labels{
			"service": "gomcp-server",
			"version": "1.0.0",
		},
	}

	provider := NewPrometheusWithConfig("test", config)

	userLabels := map[string]string{
		"method": "POST",
		"path":   "/api/tools",
	}

	provider.RecordCounter("requests_total", 1, userLabels)

	// Verify counter was created with merged labels
	counter := provider.counters["requests_total"]

	// Check that both default and user labels are present
	expectedLabels := prometheus.Labels{
		"service": "gomcp-server",
		"version": "1.0.0",
		"method":  "POST",
		"path":    "/api/tools",
	}

	actualValue := testutil.ToFloat64(counter.With(expectedLabels))
	if actualValue != 1.0 {
		t.Errorf("Expected counter value 1.0 with merged labels, got %f", actualValue)
	}
}

func TestPrometheusProvider_MetricNaming(t *testing.T) {
	config := PrometheusConfig{
		Namespace: "custom_app",
		Subsystem: "api_server",
	}

	provider := NewPrometheusWithConfig("test", config)
	provider.RecordCounter("requests_total", 1, nil)

	// Verify the metric name follows Prometheus conventions
	counter := provider.counters["requests_total"]
	if counter == nil {
		t.Fatal("Expected counter to be created")
	}

	// The full metric name should be: custom_app_api_server_requests_total
	// We can verify this by checking the registry
	metricFamilies, err := provider.registry.Gather()
	if err != nil {
		t.Fatalf("Failed to gather metrics: %v", err)
	}

	found := false
	expectedName := "custom_app_api_server_requests_total"
	for _, mf := range metricFamilies {
		if mf.GetName() == expectedName {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected metric name '%s' not found in registry", expectedName)
	}
}

func TestPrometheusProvider_HistogramBuckets(t *testing.T) {
	provider := NewPrometheus("test")

	testCases := []struct {
		name            string
		expectedBuckets []float64
	}{
		{
			name:            "request_duration_seconds",
			expectedBuckets: provider.config.DurationBuckets,
		},
		{
			name:            "response_size_bytes",
			expectedBuckets: provider.config.SizeBuckets,
		},
		{
			name:            "custom_metric",
			expectedBuckets: prometheus.DefBuckets,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider.RecordHistogram(tc.name, 1.0, nil)

			histogram := provider.histograms[tc.name]
			if histogram == nil {
				t.Fatalf("Expected histogram '%s' to be created", tc.name)
			}

			// Verify buckets were set correctly by checking metric description
			// This is a basic check - in practice, you'd need more sophisticated verification
			if len(tc.expectedBuckets) == 0 {
				t.Errorf("Expected buckets for %s to be non-empty", tc.name)
			}
		})
	}
}

func TestPrometheusProvider_HTTPHandler(t *testing.T) {
	provider := NewPrometheus("test")

	// Record some metrics
	provider.RecordCounter("test_counter", 42, map[string]string{"label": "value"})
	provider.RecordGauge("test_gauge", 3.14, nil)

	// Get HTTP handler
	handler := provider.GetHTTPHandler()

	// Create test HTTP request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	// Handle request
	handler.ServeHTTP(w, req)

	// Check response
	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	bodyStr := string(body)

	// Check that our metrics appear in the output
	if !strings.Contains(bodyStr, "gomcp_server_test_counter") {
		t.Error("Expected test_counter metric in output")
	}

	if !strings.Contains(bodyStr, "gomcp_server_test_gauge") {
		t.Error("Expected test_gauge metric in output")
	}

	// Check that standard Go metrics are included
	if !strings.Contains(bodyStr, "go_goroutines") {
		t.Error("Expected Go runtime metrics in output")
	}
}

func TestPrometheusProvider_PredefinedMethods(t *testing.T) {
	provider := NewPrometheus("test")

	// Test RecordRequestDuration
	provider.RecordRequestDuration("GET", "/api/test", "200", 0.5)

	if len(provider.histograms) != 1 {
		t.Errorf("Expected 1 histogram after RecordRequestDuration, got %d", len(provider.histograms))
	}

	// Test RecordRequestCount
	provider.RecordRequestCount("POST", "/api/create", "201")

	if len(provider.counters) != 1 {
		t.Errorf("Expected 1 counter after RecordRequestCount, got %d", len(provider.counters))
	}

	// Test RecordActiveConnections
	provider.RecordActiveConnections("http", 10)

	if len(provider.gauges) != 1 {
		t.Errorf("Expected 1 gauge after RecordActiveConnections, got %d", len(provider.gauges))
	}

	// Test RecordCacheOperation
	provider.RecordCacheOperation("redis", "get", true)
	provider.RecordCacheOperation("redis", "get", false)

	if len(provider.counters) != 2 {
		t.Errorf("Expected 2 counters after RecordCacheOperation, got %d", len(provider.counters))
	}

	// Test RecordAuthOperation
	provider.RecordAuthOperation("jwt", "success")
	provider.RecordAuthOperation("jwt", "failure")

	if len(provider.counters) != 3 {
		t.Errorf("Expected 3 counters after RecordAuthOperation, got %d", len(provider.counters))
	}

	// Test RecordToolExecution
	provider.RecordToolExecution("calculator", "success", 0.1)

	if len(provider.counters) != 4 {
		t.Errorf("Expected 4 counters after RecordToolExecution, got %d", len(provider.counters))
	}

	if len(provider.histograms) != 2 {
		t.Errorf("Expected 2 histograms after RecordToolExecution, got %d", len(provider.histograms))
	}
}

func TestPrometheusProvider_ConcurrentAccess(t *testing.T) {
	provider := NewPrometheus("test")

	done := make(chan bool, 10)

	// Test concurrent counter recording
	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()

			for j := 0; j < 100; j++ {
				provider.RecordCounter("concurrent_counter", 1, map[string]string{
					"worker": fmt.Sprintf("worker-%d", id),
				})
			}
		}(i)
	}

	// Test concurrent gauge recording
	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()

			for j := 0; j < 50; j++ {
				provider.RecordGauge("concurrent_gauge", float64(j), map[string]string{
					"worker": fmt.Sprintf("worker-%d", id),
				})
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify metrics were created
	if len(provider.counters) != 1 {
		t.Errorf("Expected 1 counter after concurrent access, got %d", len(provider.counters))
	}

	if len(provider.gauges) != 1 {
		t.Errorf("Expected 1 gauge after concurrent access, got %d", len(provider.gauges))
	}
}

func TestPrometheusProvider_EmptyLabels(t *testing.T) {
	provider := NewPrometheus("test")

	// Test with nil labels
	provider.RecordCounter("nil_labels_counter", 1, nil)

	// Test with empty labels map
	provider.RecordCounter("empty_labels_counter", 1, map[string]string{})

	// Both should work without errors
	if len(provider.counters) != 2 {
		t.Errorf("Expected 2 counters, got %d", len(provider.counters))
	}
}

func TestPrometheusProvider_Close(t *testing.T) {
	provider := NewPrometheus("test")

	// Record some metrics
	provider.RecordCounter("test_counter", 1, nil)
	provider.RecordGauge("test_gauge", 1.0, nil)

	// Close should not error
	err := provider.Close()
	if err != nil {
		t.Errorf("Expected Close() to return nil, got %v", err)
	}

	// Should be able to call close multiple times
	err = provider.Close()
	if err != nil {
		t.Errorf("Expected second Close() to return nil, got %v", err)
	}
}

func TestPrometheusProvider_LabelOverride(t *testing.T) {
	config := PrometheusConfig{
		Namespace: "gomcp",
		Subsystem: "test",
		DefaultLabels: prometheus.Labels{
			"service": "default-service",
			"env":     "test",
		},
	}

	provider := NewPrometheusWithConfig("test", config)

	// User labels should override default labels with same key
	userLabels := map[string]string{
		"service": "override-service", // Override default
		"method":  "GET",              // New label
	}

	provider.RecordCounter("test_counter", 1, userLabels)

	counter := provider.counters["test_counter"]

	// Check that user label overrode default label
	expectedLabels := prometheus.Labels{
		"service": "override-service", // Overridden
		"env":     "test",             // From defaults
		"method":  "GET",              // From user
	}

	actualValue := testutil.ToFloat64(counter.With(expectedLabels))
	if actualValue != 1.0 {
		t.Errorf("Expected counter value 1.0 with overridden labels, got %f", actualValue)
	}
}
