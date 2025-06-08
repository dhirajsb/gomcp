package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp/pkg/builder"
)

// Example demonstrating basic metrics through public API
func main() {
	fmt.Println("=== Go MCP Basic Metrics Demo ===")
	fmt.Println("This example shows how to create a server with metrics-enabled features")
	fmt.Println()

	// Create server with features that include built-in metrics
	server, err := builder.QuickDev("metrics-demo", "1.0.0").
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}

	// Register a simple tool for demonstration
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

	err = server.RegisterTool("calculator", calculator)
	if err != nil {
		log.Printf("Failed to register tool: %v", err)
	}

	fmt.Printf("✓ Created MCP server '%s' with metrics-enabled features\n", server.Name())
	fmt.Printf("✓ Registered calculator tool\n")
	fmt.Printf("✓ Server includes logging, caching, telemetry, and metrics\n")
	fmt.Println()
	fmt.Println("In a real application, the server would:")
	fmt.Println("- Collect request/response metrics")
	fmt.Println("- Track authentication and authorization events")
	fmt.Println("- Monitor cache hit/miss rates")
	fmt.Println("- Record security validation results")
	fmt.Println("- Measure latency and throughput")
	fmt.Println()
	fmt.Println("=== Metrics Demo Complete ===")

	// Clean shutdown
	server.Close()
}
