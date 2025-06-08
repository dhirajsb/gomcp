package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp/pkg/gomcp"
	"github.com/dhirajsb/gomcp/pkg/builder"
	"github.com/dhirajsb/gomcp/internal/logging"
)

func main() {
	// Example 1: Minimal server with no optional features
	fmt.Println("=== Example 1: Minimal Server ===")
	minimalServer := gomcp.Minimal("minimal-server", "1.0.0")
	fmt.Printf("Minimal server features: %+v\n", minimalServer.GetFeatureSummary())

	// Example 2: Development server with common development features
	fmt.Println("\n=== Example 2: Development Server ===")
	devServer := gomcp.Development("dev-server", "1.0.0")
	fmt.Printf("Development server features: %+v\n", devServer.GetFeatureSummary())

	// Example 3: Production server with all production features
	fmt.Println("\n=== Example 3: Production Server ===")
	prodServer := gomcp.Production("prod-server", "1.0.0")
	fmt.Printf("Production server features: %+v\n", prodServer.GetFeatureSummary())

	// Example 4: Custom server with specific features
	fmt.Println("\n=== Example 4: Custom Server ===")
	customServer := gomcp.NewBuilder("custom-server", "2.0.0").
		WithLogger(builder.ConsoleLogger("app", "info")).
		WithLogger(builder.JSONLogger("audit", "warn")).
		WithCache(builder.MediumCache("default")).
		WithCache(builder.SmallCache("sessions")).
		WithAuth(builder.JWTAuth("jwt", "secret-key")).
		WithSecurity(builder.StrictValidator("security")).
		WithTelemetry(builder.StdoutTelemetry("custom")).
		WithMetrics(builder.SimpleMetrics("metrics"))

	fmt.Printf("Custom server features: %+v\n", customServer.GetFeatureSummary())

	// Example 5: Using preset configurations
	fmt.Println("\n=== Example 5: Preset Configurations ===")
	presetServer := gomcp.NewBuilder("preset-server", "1.0.0").
		WithBasicLogging().
		WithBasicCaching().
		WithTelemetry(builder.DevTelemetry("preset"))

	fmt.Printf("Preset server features: %+v\n", presetServer.GetFeatureSummary())

	// Example 6: Quick development setup
	fmt.Println("\n=== Example 6: Quick Development Setup ===")
	quickDevServer := gomcp.QuickDev("quick-dev", "1.0.0")
	fmt.Printf("Quick dev server features: %+v\n", quickDevServer.GetFeatureSummary())

	// Example 7: Quick production setup
	fmt.Println("\n=== Example 7: Quick Production Setup ===")
	quickProdServer := gomcp.QuickProd("quick-prod", "1.0.0")
	fmt.Printf("Quick prod server features: %+v\n", quickProdServer.GetFeatureSummary())

	// Example 8: Building and configuring a server
	fmt.Println("\n=== Example 8: Building and Using Server ===")
	
	// Build the server
	server, err := gomcp.NewBuilder("example-server", "1.0.0").
		WithLogger(builder.InfoLogger("main")).
		WithCache(builder.SmallCache("example")).
		WithTelemetry(builder.StdoutTelemetry("example")).
		Build()
	
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}

	fmt.Printf("Built server successfully\n")

	// Register some tools
	server.RegisterTool("hello", func(name string) string {
		return fmt.Sprintf("Hello, %s!", name)
	})

	server.RegisterTool("add", func(a, b int) int {
		return a + b
	})

	// Access configured features
	loggers := server.GetLoggers()
	fmt.Printf("Server has %d loggers configured\n", len(loggers))
	
	for _, logger := range loggers {
		logger.Log(logging.LogLevelInfo, "Server started", map[string]interface{}{
			"server": "example-server",
			"version": "1.0.0",
		})
	}

	caches := server.GetCaches()
	fmt.Printf("Server has %d caches configured\n", len(caches))
	
	if len(caches) > 0 {
		cache := caches[0]
		cache.Set("example-key", "example-value", 0)
		
		if value, err := cache.Get("example-key"); err == nil {
			fmt.Printf("Retrieved from cache: %v\n", value)
		}
	}

	// Example 9: Multiple instances of the same feature type
	fmt.Println("\n=== Example 9: Multiple Feature Instances ===")
	multiServer := gomcp.NewBuilder("multi-server", "1.0.0").
		WithLogger(builder.ConsoleLogger("console", "info")).    // Console logger
		WithLogger(builder.JSONLogger("file", "debug")).         // File logger  
		WithLogger(builder.JSONLogger("audit", "warn")).         // Audit logger
		WithCache(builder.SmallCache("l1")).                     // L1 cache
		WithCache(builder.MediumCache("l2")).                    // L2 cache
		WithCache(builder.LargeCache("persistent"))              // Persistent cache

	builtMultiServer, err := multiServer.Build()
	if err != nil {
		log.Fatalf("Failed to build multi server: %v", err)
	}

	fmt.Printf("Multi-server has %d loggers and %d caches\n", 
		len(builtMultiServer.GetLoggers()), len(builtMultiServer.GetCaches()))

	// Access specific features by name
	if l1Cache := builtMultiServer.GetCacheByName("l1"); l1Cache != nil {
		fmt.Printf("Found L1 cache: %s\n", l1Cache.Name())
	}

	if auditLogger := builtMultiServer.GetLoggerByName("audit"); auditLogger != nil {
		auditLogger.Log(logging.LogLevelWarn, "Audit event", map[string]interface{}{
			"action": "server_start",
			"user": "system",
		})
	}

	// Clean shutdown
	fmt.Println("\n=== Shutting Down ===")
	if err := server.Close(); err != nil {
		log.Printf("Error during shutdown: %v", err)
	}
	
	if err := builtMultiServer.Close(); err != nil {
		log.Printf("Error during multi-server shutdown: %v", err)
	}

	fmt.Println("Examples completed successfully!")
}