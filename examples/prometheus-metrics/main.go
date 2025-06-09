package main

import (
	"log"
	"net/http"
	"time"

	"github.com/dhirajsb/gomcp/pkg/builder"
)

func main() {
	// Example 1: Basic Prometheus metrics
	basicPrometheusExample()

	// Example 2: Prometheus with custom configuration
	customPrometheusExample()

	// Example 3: Production metrics setup
	productionMetricsExample()

	// Example 4: Embedded HTTP handler
	embeddedHandlerExample()

	// Example 5: Custom metrics recording
	customMetricsExample()
}

func basicPrometheusExample() {
	log.Println("=== Basic Prometheus Metrics Example ===")

	// Create server with Prometheus metrics
	server, err := builder.New("prometheus-basic", "1.0.0").
		WithMetrics(builder.PrometheusMetrics("basic")).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	// Get metrics provider
	metrics := server.GetMetrics()
	if len(metrics) > 0 {
		// Record some example metrics
		metricsProvider := metrics[0]
		metricsProvider.RecordCounter("example_requests_total", 5, map[string]string{
			"method": "GET",
			"status": "200",
		})

		metricsProvider.RecordGauge("example_active_connections", 42, map[string]string{
			"protocol": "http",
		})

		metricsProvider.RecordHistogram("example_request_duration_seconds", 0.25, map[string]string{
			"endpoint": "/api/test",
		})

		log.Printf("Recorded basic metrics - check http://localhost:9090/metrics")
	}

	log.Printf("Server %s ready with Prometheus metrics", server.Name())
}

func customPrometheusExample() {
	log.Println("\n=== Custom Prometheus Configuration Example ===")

	// Create custom Prometheus configuration
	config := &builder.PrometheusConfig{
		Namespace: "myapp",
		Subsystem: "api",
		DefaultLabels: map[string]string{
			"service": "gomcp-server",
			"env":     "development",
		},
		EnableHTTPHandler: true,
		HTTPPath:          "/custom-metrics",
		HTTPPort:          8080,
		DurationBuckets:   []float64{0.001, 0.01, 0.1, 0.5, 1.0, 5.0},
		SizeBuckets:       []float64{1024, 10240, 102400, 1048576},
	}

	server, err := builder.New("prometheus-custom", "1.0.0").
		WithMetrics(builder.PrometheusMetricsWithConfig("custom", config)).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	log.Printf("Custom Prometheus metrics available at http://localhost:8080/custom-metrics")
	log.Printf("Namespace: %s, Subsystem: %s", config.Namespace, config.Subsystem)
}

func productionMetricsExample() {
	log.Println("\n=== Production Metrics Example ===")

	// Use production-ready metrics configuration
	server, err := builder.Production("prometheus-prod", "2.1.0").
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	// Get metrics and record some production-style metrics
	metrics := server.GetMetrics()
	if len(metrics) > 0 {
		metricsProvider := metrics[0]

		// Record business metrics
		metricsProvider.RecordCounter("api_calls_total", 1, map[string]string{
			"endpoint": "/api/v1/users",
			"method":   "GET",
			"status":   "200",
		})

		metricsProvider.RecordHistogram("response_time_seconds", 0.15, map[string]string{
			"endpoint": "/api/v1/users",
			"method":   "GET",
		})

		metricsProvider.RecordGauge("active_sessions", 127, map[string]string{
			"type": "authenticated",
		})

		// Record infrastructure metrics
		metricsProvider.RecordGauge("memory_usage_bytes", 134217728, map[string]string{
			"type": "heap",
		})

		metricsProvider.RecordCounter("cache_operations_total", 1, map[string]string{
			"cache":     "redis",
			"operation": "get",
			"result":    "hit",
		})

		log.Printf("Production metrics recorded - service: prometheus-prod, version: 2.1.0")
		log.Printf("Metrics endpoint: http://localhost:9090/metrics")
	}
}

func embeddedHandlerExample() {
	log.Println("\n=== Embedded HTTP Handler Example ===")

	server, err := builder.New("embedded-metrics", "1.0.0").
		WithMetrics(builder.PrometheusMetricsWithHTTP("embedded", 8081, "/metrics")).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	// In a real application, you'd embed the metrics handler in your existing HTTP server
	mux := http.NewServeMux()

	// Add your application routes
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// You could also get the metrics handler and embed it
	// Note: This is just for demonstration - normally you'd get the actual provider
	log.Printf("Example embedded server would run on port 8081")
	log.Printf("Metrics would be available at /metrics")
	log.Printf("Health check would be available at /health")
}

func customMetricsExample() {
	log.Println("\n=== Custom Metrics Recording Example ===")

	server, err := builder.New("custom-recording", "1.0.0").
		WithMetrics(builder.PrometheusMetrics("recording")).
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	metrics := server.GetMetrics()
	if len(metrics) > 0 {
		provider := metrics[0]

		// Simulate application metrics over time
		for i := 0; i < 10; i++ {
			// HTTP request metrics
			provider.RecordCounter("http_requests_total", 1, map[string]string{
				"method": "GET",
				"path":   "/api/users",
				"status": "200",
			})

			// Request duration (simulate varying response times)
			duration := 0.1 + float64(i)*0.05
			provider.RecordHistogram("http_request_duration_seconds", duration, map[string]string{
				"method": "GET",
				"path":   "/api/users",
			})

			// Error metrics
			if i%3 == 0 {
				provider.RecordCounter("http_requests_total", 1, map[string]string{
					"method": "GET",
					"path":   "/api/users",
					"status": "500",
				})
			}

			// System metrics
			provider.RecordGauge("system_memory_usage_ratio", 0.65+float64(i)*0.02, map[string]string{
				"type": "heap",
			})

			provider.RecordGauge("system_cpu_usage_ratio", 0.25+float64(i)*0.03, map[string]string{
				"core": "total",
			})

			// Business metrics
			provider.RecordCounter("user_actions_total", 1, map[string]string{
				"action": "login",
				"result": "success",
			})

			// Cache metrics
			provider.RecordCounter("cache_requests_total", 1, map[string]string{
				"cache":  "redis",
				"result": "hit",
			})

			time.Sleep(100 * time.Millisecond)
		}

		log.Printf("Recorded 10 rounds of custom metrics")
		log.Printf("Check http://localhost:9090/metrics for complete metrics")
	}
}

// Example of how you'd use Prometheus metrics in a real HTTP server
func realWorldExample() {
	log.Println("\n=== Real World Integration Example ===")

	// Create server with Prometheus metrics
	server, err := builder.New("real-world", "1.0.0").
		WithMetrics(builder.PrometheusMetricsWithHTTP("app", 9091, "/metrics")).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	metrics := server.GetMetrics()
	var metricsProvider interface{}
	if len(metrics) > 0 {
		metricsProvider = metrics[0]
	}

	// Set up HTTP server with middleware
	mux := http.NewServeMux()

	// Add metrics middleware
	mux.HandleFunc("/api/users", func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Your actual handler logic here
		time.Sleep(50 * time.Millisecond) // Simulate work
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"users": []}`))

		// Record metrics
		if provider, ok := metricsProvider.(interface {
			RecordCounter(string, int64, map[string]string)
			RecordHistogram(string, float64, map[string]string)
		}); ok {
			duration := time.Since(start).Seconds()

			provider.RecordCounter("http_requests_total", 1, map[string]string{
				"method": r.Method,
				"path":   "/api/users",
				"status": "200",
			})

			provider.RecordHistogram("http_request_duration_seconds", duration, map[string]string{
				"method": r.Method,
				"path":   "/api/users",
			})
		}
	})

	log.Printf("Real-world example server would listen on :9091")
	log.Printf("API endpoint: /api/users")
	log.Printf("Metrics endpoint: /metrics")

	// In real code, you'd start the server:
	// log.Fatal(http.ListenAndServe(":9091", mux))
}

// Example usage patterns:
//
// 1. Basic Prometheus metrics:
//   metrics := builder.PrometheusMetrics("my-service")
//
// 2. Prometheus with custom HTTP endpoint:
//   metrics := builder.PrometheusMetricsWithHTTP("my-service", 8080, "/metrics")
//
// 3. Custom configuration:
//   config := &builder.PrometheusConfig{
//     Namespace: "myapp",
//     Subsystem: "api",
//     DefaultLabels: map[string]string{"env": "prod"},
//     HTTPPort: 9090,
//   }
//   metrics := builder.PrometheusMetricsWithConfig("my-service", config)
//
// 4. Production setup:
//   metrics := builder.ProductionMetrics("my-service", "1.0.0")
//
// 5. Recording metrics:
//   provider.RecordCounter("requests_total", 1, map[string]string{"method": "GET"})
//   provider.RecordGauge("active_connections", 42, nil)
//   provider.RecordHistogram("request_duration", 0.5, map[string]string{"endpoint": "/api"})
//
// 6. Integration with existing HTTP server:
//   handler := provider.GetHTTPHandler()
//   mux.Handle("/metrics", handler)
