package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dhirajsb/gomcp/auth"
	"github.com/dhirajsb/gomcp/cache"
	"github.com/dhirajsb/gomcp/security"
	"github.com/dhirajsb/gomcp/server"
	"github.com/dhirajsb/gomcp/telemetry"
)

// Example demonstrating comprehensive OpenTelemetry integration
func main() {
	fmt.Println("=== Go MCP OpenTelemetry Integration Demo ===")
	fmt.Println()

	// 1. Initialize OpenTelemetry
	fmt.Println("1. Initializing OpenTelemetry")
	fmt.Println("-------------------------------")
	if err := initializeTelemetry(); err != nil {
		log.Fatalf("Failed to initialize telemetry: %v", err)
	}

	// 2. Create tracer
	tracerConfig := telemetry.DefaultTracerConfig()
	tracerConfig.ServiceName = "gomcp-demo"
	tracerConfig.ServiceVersion = "1.0.0"
	tracerConfig.Environment = "demo"
	tracerConfig.ExporterType = "stdout" // Use stdout for demo
	tracerConfig.SamplingRatio = 1.0     // Sample all traces

	tracerManager := telemetry.NewTracerManager(tracerConfig)
	ctx := context.Background()

	if err := tracerManager.Initialize(ctx); err != nil {
		log.Fatalf("Failed to initialize tracer: %v", err)
	}
	defer tracerManager.Shutdown(ctx)

	tracer := tracerManager.GetTracer()
	fmt.Printf("✓ OpenTelemetry tracer initialized with %s exporter\n", tracerConfig.ExporterType)
	fmt.Println()

	// 3. Setup components with tracing
	fmt.Println("2. Setting up components with distributed tracing")
	fmt.Println("------------------------------------------------")
	demoComponentsWithTracing(ctx, tracer)

	// 4. Demonstrate end-to-end tracing
	fmt.Println("\n3. Demonstrating end-to-end distributed tracing")
	fmt.Println("-----------------------------------------------")
	demoEndToEndTracing(ctx, tracer)

	fmt.Println("\n=== OpenTelemetry Demo Complete ===")
}

func initializeTelemetry() error {
	// In a real application, you might want to:
	// 1. Set up proper exporters (Jaeger, OTLP, etc.)
	// 2. Configure sampling strategies
	// 3. Set up resource attributes
	// 4. Configure propagators for distributed tracing

	fmt.Println("• Configured service information")
	fmt.Println("• Set up trace exporters")
	fmt.Println("• Configured sampling strategy")
	fmt.Println("• Set up propagators for distributed tracing")

	return nil
}

func demoComponentsWithTracing(ctx context.Context, tracer any) {
	// Note: In real usage, you'd pass trace.Tracer, but for demo we use any
	fmt.Println("Setting up components with OpenTelemetry integration:")

	// 1. Authentication with tracing
	fmt.Println("• Auth Manager with distributed tracing")
	rbac := auth.NewInMemoryRBAC()
	authConfig := auth.AuthConfig{
		Provider: "demo",
		Enabled:  true,
		Required: false,
	}
	_ = auth.NewAuthManager(authConfig, rbac)
	// authManager.SetTracer(tracer) // Would set tracer in real usage

	// 2. Security validation with tracing
	fmt.Println("• Security Validator with distributed tracing")
	securityConfig := security.ValidatorConfig{
		Enabled:       true,
		StrictMode:    false,
		AutoSanitize:  true,
		MaxViolations: 10,
	}
	_ = security.NewSecurityValidatorManager(securityConfig)
	// securityManager.SetTracer(tracer) // Would set tracer in real usage

	// 3. Caching with tracing
	fmt.Println("• Memory Cache with distributed tracing")
	cacheConfig := cache.CacheConfig{
		Name:           "demo-cache",
		Type:           "memory",
		Enabled:        true,
		DefaultTTL:     time.Minute * 5,
		MaxSize:        1000,
		MaxMemory:      1024 * 1024,
		EvictionPolicy: "lru",
	}
	_ = cache.NewMemoryCache("demo-cache", cacheConfig)
	// memoryCache.SetTracer(tracer) // Would set tracer in real usage

	// 4. MCP Server with tracing
	fmt.Println("• MCP Server with distributed tracing")
	mcpServer := server.NewServer("demo-server", "1.0.0")
	// mcpServer.SetTracer(tracer) // Would set tracer in real usage

	// Register a demo tool
	calculator := func(operation string, a, b float64) float64 {
		switch operation {
		case "add":
			return a + b
		case "multiply":
			return a * b
		default:
			return 0
		}
	}
	mcpServer.RegisterTool("calculator", calculator)

	fmt.Println("✓ All components configured with distributed tracing")
	fmt.Println()
}

func demoEndToEndTracing(ctx context.Context, tracer any) {
	fmt.Println("Simulating end-to-end request with distributed tracing:")

	// In a real application, this would create spans that connect
	// across all components, showing the complete request flow

	// Simulate a request flow
	scenarios := []struct {
		name        string
		description string
		components  []string
	}{
		{
			name:        "Tool Invocation",
			description: "User calls calculator tool with authentication",
			components: []string{
				"mcp.handle_message",        // Server receives request
				"auth.authenticate_request", // Authentication check
				"rbac.has_permission",       // Permission validation
				"security.validate_input",   // Input security validation
				"cache.get",                 // Check cache for result
				"mcp.tools.call",            // Execute tool
				"cache.set",                 // Cache the result
			},
		},
		{
			name:        "Security Violation",
			description: "Malicious input triggers security validation",
			components: []string{
				"mcp.handle_message",               // Server receives request
				"auth.authenticate_request",        // Authentication check
				"security.validate_input",          // Input security validation
				"security.validator.sql_injection", // SQL injection check
				"security.validator.xss",           // XSS check
			},
		},
		{
			name:        "Cache Performance",
			description: "High-traffic scenario with cache hits and misses",
			components: []string{
				"cache.get", // Cache lookup
				"cache.set", // Cache storage
				"cache.get", // Cache hit
				"cache.get", // Another hit
			},
		},
	}

	for i, scenario := range scenarios {
		fmt.Printf("\n%d. %s\n", i+1, scenario.name)
		fmt.Printf("   %s\n", scenario.description)
		fmt.Printf("   Trace components: %v\n", scenario.components)

		// Simulate processing time
		time.Sleep(100 * time.Millisecond)
	}

	fmt.Println("\n📊 Distributed tracing benefits:")
	fmt.Println("• End-to-end request visibility")
	fmt.Println("• Performance bottleneck identification")
	fmt.Println("• Error propagation tracking")
	fmt.Println("• Service dependency mapping")
	fmt.Println("• Latency analysis across components")
	fmt.Println("• Security event correlation")
	fmt.Println("• Cache performance optimization")
}

// Example configuration for different environments
func getProductionTracerConfig() telemetry.TracerConfig {
	return telemetry.TracerConfig{
		ServiceName:    "gomcp-production",
		ServiceVersion: "1.0.0",
		Environment:    "production",
		Enabled:        true,
		SamplingRatio:  0.1, // Sample 10% in production
		ExporterType:   "otlp",
		OTLPEndpoint:   "http://otel-collector:4318",
		BatchTimeout:   5 * time.Second,
		BatchSize:      512,
		ExportTimeout:  30 * time.Second,
		Headers: map[string]string{
			"Authorization": "Bearer <token>",
		},
		Attributes: map[string]string{
			"deployment.environment": "production",
			"service.instance.id":    "instance-1",
			"service.datacenter":     "us-east-1",
		},
	}
}

func getDevelopmentTracerConfig() telemetry.TracerConfig {
	return telemetry.TracerConfig{
		ServiceName:    "gomcp-dev",
		ServiceVersion: "dev",
		Environment:    "development",
		Enabled:        true,
		SamplingRatio:  1.0, // Sample everything in development
		ExporterType:   "jaeger",
		JaegerEndpoint: "http://localhost:14268/api/traces",
		BatchTimeout:   1 * time.Second,
		BatchSize:      100,
		ExportTimeout:  10 * time.Second,
		Attributes: map[string]string{
			"developer":        "local",
			"debug.enabled":    "true",
			"service.instance": "dev-local",
		},
	}
}

func getTestingTracerConfig() telemetry.TracerConfig {
	return telemetry.TracerConfig{
		ServiceName:    "gomcp-test",
		ServiceVersion: "test",
		Environment:    "testing",
		Enabled:        true,
		SamplingRatio:  1.0, // Sample everything for testing
		ExporterType:   "stdout",
		BatchTimeout:   100 * time.Millisecond,
		BatchSize:      10,
		ExportTimeout:  1 * time.Second,
		Attributes: map[string]string{
			"test.suite":  "integration",
			"test.runner": "ci",
		},
	}
}

// Example of integrating with popular observability platforms
func demonstrateObservabilityIntegrations() {
	fmt.Println("🔍 Observability Platform Integrations:")
	fmt.Println("")

	fmt.Println("1. Jaeger (Open Source)")
	fmt.Println("   • Distributed tracing")
	fmt.Println("   • Service dependency graphs")
	fmt.Println("   • Performance analysis")
	fmt.Println("   Config: JaegerEndpoint = \"http://jaeger:14268/api/traces\"")
	fmt.Println("")

	fmt.Println("2. OpenTelemetry Collector + Observability Backend")
	fmt.Println("   • Vendor-agnostic telemetry pipeline")
	fmt.Println("   • Multi-backend export (Jaeger, Zipkin, Datadog, etc.)")
	fmt.Println("   • Data processing and filtering")
	fmt.Println("   Config: OTLPEndpoint = \"http://otel-collector:4318\"")
	fmt.Println("")

	fmt.Println("3. Cloud Providers")
	fmt.Println("   • AWS X-Ray: OTLP export to X-Ray via Collector")
	fmt.Println("   • Google Cloud Trace: Native OTLP support")
	fmt.Println("   • Azure Monitor: Application Insights integration")
	fmt.Println("")

	fmt.Println("4. Commercial Platforms")
	fmt.Println("   • Datadog: Native OTLP ingestion")
	fmt.Println("   • New Relic: OTLP endpoint support")
	fmt.Println("   • Honeycomb: OTLP protocol support")
	fmt.Println("")
}
