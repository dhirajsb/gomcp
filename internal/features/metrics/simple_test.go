package metrics

import (
	"fmt"
	"testing"
)

func TestNewSimple(t *testing.T) {
	provider := NewSimple("test-metrics")

	if provider.name != "test-metrics" {
		t.Errorf("Expected name 'test-metrics', got '%s'", provider.name)
	}

	// Simple implementation doesn't need internal state validation
}

func TestSimpleMetricsProvider_Name(t *testing.T) {
	provider := NewSimple("my-metrics")

	if provider.Name() != "my-metrics" {
		t.Errorf("Expected name 'my-metrics', got '%s'", provider.Name())
	}
}

func TestSimpleMetricsProvider_RecordCounter(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{
		"service": "test-service",
		"method":  "test-method",
	}

	// Record counter multiple times
	provider.RecordCounter("test_counter", 1, labels)
	provider.RecordCounter("test_counter", 5, labels)
	provider.RecordCounter("test_counter", 3, labels)

	// Check that counter was recorded (implementation detail - just ensure no panic)
	// In a real implementation, you might have a way to retrieve counter values
}

func TestSimpleMetricsProvider_RecordCounter_NilLabels(t *testing.T) {
	provider := NewSimple("test")

	// Should handle nil labels gracefully
	provider.RecordCounter("test_counter", 1, nil)
	provider.RecordCounter("test_counter", 2, nil)
}

func TestSimpleMetricsProvider_RecordCounter_EmptyLabels(t *testing.T) {
	provider := NewSimple("test")

	emptyLabels := map[string]string{}

	// Should handle empty labels gracefully
	provider.RecordCounter("test_counter", 1, emptyLabels)
	provider.RecordCounter("test_counter", 2, emptyLabels)
}

func TestSimpleMetricsProvider_RecordCounter_DifferentLabels(t *testing.T) {
	provider := NewSimple("test")

	labels1 := map[string]string{"service": "service-1"}
	labels2 := map[string]string{"service": "service-2"}
	labels3 := map[string]string{"service": "service-1", "method": "get"}

	// Same counter name with different labels should be treated separately
	provider.RecordCounter("requests_total", 1, labels1)
	provider.RecordCounter("requests_total", 2, labels2)
	provider.RecordCounter("requests_total", 3, labels3)
}

func TestSimpleMetricsProvider_RecordGauge(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{
		"instance": "instance-1",
	}

	// Record gauge values
	provider.RecordGauge("memory_usage", 100.5, labels)
	provider.RecordGauge("memory_usage", 95.2, labels)  // Should overwrite
	provider.RecordGauge("memory_usage", 102.7, labels) // Should overwrite again
}

func TestSimpleMetricsProvider_RecordGauge_MultipleMetrics(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{"host": "localhost"}

	// Record different gauge metrics
	provider.RecordGauge("cpu_usage", 45.5, labels)
	provider.RecordGauge("memory_usage", 78.9, labels)
	provider.RecordGauge("disk_usage", 23.1, labels)
	provider.RecordGauge("network_io", 1024.0, labels)
}

func TestSimpleMetricsProvider_RecordHistogram(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{
		"endpoint": "/api/users",
		"method":   "GET",
	}

	// Record histogram values (latencies)
	provider.RecordHistogram("request_duration", 0.1, labels)
	provider.RecordHistogram("request_duration", 0.5, labels)
	provider.RecordHistogram("request_duration", 1.2, labels)
	provider.RecordHistogram("request_duration", 0.8, labels)
	provider.RecordHistogram("request_duration", 0.3, labels)
}

func TestSimpleMetricsProvider_RecordHistogram_DifferentMetrics(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{"service": "api"}

	// Record different histogram metrics
	provider.RecordHistogram("request_duration", 0.5, labels)
	provider.RecordHistogram("db_query_duration", 0.02, labels)
	provider.RecordHistogram("cache_lookup_duration", 0.001, labels)
}

func TestSimpleMetricsProvider_Close(t *testing.T) {
	provider := NewSimple("test")

	// Record some metrics
	provider.RecordCounter("test_counter", 1, nil)
	provider.RecordGauge("test_gauge", 42.0, nil)
	provider.RecordHistogram("test_histogram", 1.5, nil)

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

func TestSimpleMetricsProvider_ConcurrentAccess(t *testing.T) {
	provider := NewSimple("test")

	done := make(chan bool, 10)

	// Test concurrent counter recording
	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()

			labels := map[string]string{
				"worker_id": fmt.Sprintf("worker-%d", id),
			}

			for j := 0; j < 100; j++ {
				provider.RecordCounter("worker_operations", 1, labels)
			}
		}(i)
	}

	// Test concurrent gauge recording
	for i := 0; i < 5; i++ {
		go func(id int) {
			defer func() { done <- true }()

			labels := map[string]string{
				"gauge_id": fmt.Sprintf("gauge-%d", id),
			}

			for j := 0; j < 50; j++ {
				provider.RecordGauge("worker_status", float64(j), labels)
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Provider should still be functional
	provider.RecordCounter("final_counter", 1, nil)
}

func TestSimpleMetricsProvider_SpecialValues(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{"test": "special_values"}

	// Test counter with zero and negative values
	provider.RecordCounter("zero_counter", 0, labels)
	provider.RecordCounter("negative_counter", -5, labels) // Might be valid for decrements

	// Test gauge with special float values
	provider.RecordGauge("zero_gauge", 0.0, labels)
	provider.RecordGauge("negative_gauge", -42.5, labels)
	provider.RecordGauge("large_gauge", 1e10, labels)
	provider.RecordGauge("small_gauge", 1e-10, labels)

	// Test histogram with edge cases
	provider.RecordHistogram("zero_histogram", 0.0, labels)
	provider.RecordHistogram("small_histogram", 1e-9, labels)
	provider.RecordHistogram("large_histogram", 3600.0, labels) // 1 hour
}

func TestSimpleMetricsProvider_LargeLabels(t *testing.T) {
	provider := NewSimple("test")

	// Create labels with many keys
	largeLabels := map[string]string{
		"service":     "my-service",
		"version":     "1.0.0",
		"environment": "production",
		"region":      "us-east-1",
		"instance":    "i-1234567890abcdef0",
		"cluster":     "production-cluster",
		"namespace":   "default",
		"pod":         "my-service-deployment-abc123-xyz789",
		"container":   "my-service-container",
		"node":        "ip-10-0-1-100.ec2.internal",
	}

	// Should handle large label sets
	provider.RecordCounter("large_labels_counter", 1, largeLabels)
	provider.RecordGauge("large_labels_gauge", 42.0, largeLabels)
	provider.RecordHistogram("large_labels_histogram", 1.5, largeLabels)
}

func TestSimpleMetricsProvider_SpecialCharactersInNames(t *testing.T) {
	provider := NewSimple("test")

	labels := map[string]string{"test": "special_chars"}

	specialNames := []string{
		"metric_with_underscores",
		"metric-with-dashes",
		"metric.with.dots",
		"metric/with/slashes",
		"metric with spaces",
		"metric@with#special$chars%",
		"UPPERCASE_METRIC",
		"mixedCaseMetric",
	}

	for _, name := range specialNames {
		// Should handle special characters in metric names
		provider.RecordCounter(name+"_counter", 1, labels)
		provider.RecordGauge(name+"_gauge", 1.0, labels)
		provider.RecordHistogram(name+"_histogram", 1.0, labels)
	}
}

func TestSimpleMetricsProvider_SpecialCharactersInLabels(t *testing.T) {
	provider := NewSimple("test")

	specialLabels := map[string]string{
		"key-with-dashes":      "value-with-dashes",
		"key_with_underscores": "value_with_underscores",
		"key.with.dots":        "value.with.dots",
		"key with spaces":      "value with spaces",
		"UPPERCASE_KEY":        "UPPERCASE_VALUE",
		"mixedCaseKey":         "mixedCaseValue",
		"key@special#chars":    "value@special#chars",
		"unicode🚀key":          "unicode🎉value",
	}

	// Should handle special characters in label keys and values
	provider.RecordCounter("special_labels_counter", 1, specialLabels)
	provider.RecordGauge("special_labels_gauge", 1.0, specialLabels)
	provider.RecordHistogram("special_labels_histogram", 1.0, specialLabels)
}
