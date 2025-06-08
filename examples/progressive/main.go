package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp/pkg/builder"
)

// Example demonstrating progressive enhancement with builder pattern
func main() {
	fmt.Println("=== Progressive Enhancement Example ===")
	fmt.Println("Shows how to progressively add features using the builder pattern")
	fmt.Println()

	demonstrateConfigurations()
}

func demonstrateConfigurations() {
	fmt.Println("1. MINIMAL CONFIGURATION")
	fmt.Println("   Core MCP functionality only")
	showMinimalConfig()

	fmt.Println("\n2. DEVELOPMENT CONFIGURATION")
	fmt.Println("   Basic features for development")
	showDevelopmentConfig()

	fmt.Println("\n3. PRODUCTION CONFIGURATION")
	fmt.Println("   Full feature set for production")
	showProductionConfig()

	fmt.Println("\n4. CUSTOM CONFIGURATION")
	fmt.Println("   Pick and choose specific features")
	showCustomConfig()
}

func showMinimalConfig() {
	server, err := builder.Minimal("minimal-app", "1.0.0").Build()
	if err != nil {
		log.Printf("   ⚠ Failed to create minimal server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Features: Basic MCP server\n")
	fmt.Printf("   Benefits: Lightweight, minimal dependencies\n")

	// Register a tool to show it works
	err = server.RegisterTool("add", func(a, b float64) float64 { return a + b })
	if err == nil {
		fmt.Printf("   ✓ Core MCP functionality works\n")
	}

	server.Close()
}

func showDevelopmentConfig() {
	server, err := builder.Development("dev-app", "1.0.0").Build()
	if err != nil {
		log.Printf("   ⚠ Failed to create development server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Features: Logging + caching + telemetry\n")
	fmt.Printf("   Benefits: Good observability for development\n")
	fmt.Printf("   ✓ Development features enabled\n")

	server.Close()
}

func showProductionConfig() {
	server, err := builder.Production("prod-app", "1.0.0").Build()
	if err != nil {
		log.Printf("   ⚠ Failed to create production server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Features: Full feature set with security\n")
	fmt.Printf("   Benefits: Production-ready with full observability\n")
	fmt.Printf("   ✓ All production features enabled\n")

	server.Close()
}

func showCustomConfig() {
	server, err := builder.New("custom-app", "1.0.0").
		WithLogger(builder.ConsoleLogger("app", "info")).
		WithCache(builder.MediumCache("cache")).
		// Deliberately omitting auth and security for this example
		Build()

	if err != nil {
		log.Printf("   ⚠ Failed to create custom server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Features: Logging + caching only\n")
	fmt.Printf("   Benefits: Specific features for specific needs\n")
	fmt.Printf("   ✓ Custom feature set configured\n")

	server.Close()
}

// Additional examples showing the progression
func init() {
	fmt.Println("=== Builder Pattern Examples ===")
	fmt.Println()
	fmt.Println("The builder pattern allows you to:")
	fmt.Println("- Start simple and add features incrementally")
	fmt.Println("- Configure only the features you need")
	fmt.Println("- Use preset configurations for common scenarios")
	fmt.Println("- Maintain clean separation between public APIs and implementation")
	fmt.Println()
}
