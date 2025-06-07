package main

import (
	"context"
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp"
	"github.com/dhirajsb/gomcp/cache"
	"github.com/dhirajsb/gomcp/config"
	"github.com/dhirajsb/gomcp/logging"
	"github.com/dhirajsb/gomcp/security"
)

// Example demonstrating progressive enhancement with optional enterprise features
func main() {
	fmt.Println("=== Progressive Enhancement Example ===")
	fmt.Println()

	// Show different configuration levels
	demonstrateConfigurations()
}

func demonstrateConfigurations() {
	fmt.Println("1. MINIMAL CONFIGURATION (Core functionality only)")
	fmt.Println("   No enterprise features enabled")
	showMinimalConfig()

	fmt.Println("\n2. DEVELOPMENT CONFIGURATION (Some features for development)")
	fmt.Println("   Basic logging, caching, and telemetry for development")
	showDevelopmentConfig()

	fmt.Println("\n3. PRODUCTION CONFIGURATION (Full enterprise features)")
	fmt.Println("   All enterprise features enabled for production use")
	showProductionConfig()

	fmt.Println("\n4. CUSTOM CONFIGURATION (Pick and choose features)")
	fmt.Println("   Only specific features enabled based on needs")
	showCustomConfig()
}

func showMinimalConfig() {
	// Create minimal server - no enterprise features
	server := gomcp.NewMinimalServer("minimal-app", "1.0.0")

	fmt.Printf("   Server: %s v%s\n", server.GetConfig().Name, server.GetConfig().Version)
	fmt.Printf("   Features: %v\n", server.GetEnabledFeatures())
	fmt.Printf("   Dependencies: None (just core Go stdlib)\n")

	// This server has no enterprise features but full MCP functionality
	server.RegisterTool("add", func(a, b float64) float64 { return a + b })
	fmt.Printf("   ✓ Core MCP functionality works perfectly\n")
}

func showDevelopmentConfig() {
	// Create development configuration
	cfg := config.DevelopmentServerConfig("dev-app", "1.0.0")

	server, err := gomcp.NewEnterpriseServer(cfg)
	if err != nil {
		log.Printf("   ⚠ Failed to create server: %v", err)
		return
	}
	defer server.Shutdown(context.Background())

	fmt.Printf("   Server: %s v%s\n", cfg.Name, cfg.Version)
	fmt.Printf("   Features: %v\n", server.GetEnabledFeatures())
	fmt.Printf("   Good for: Development, debugging, local testing\n")

	// Show that features gracefully degrade if dependencies are missing
	server.LogInfo("Development server started")
	fmt.Printf("   ✓ Logging works (or falls back to standard log)\n")
}

func showProductionConfig() {
	// Create production configuration
	cfg := config.ProductionServerConfig("prod-app", "1.0.0")

	server, err := gomcp.NewEnterpriseServer(cfg)
	if err != nil {
		log.Printf("   ⚠ Failed to create server: %v", err)
		return
	}
	defer server.Shutdown(context.Background())

	fmt.Printf("   Server: %s v%s\n", cfg.Name, cfg.Version)
	fmt.Printf("   Features: %v\n", server.GetEnabledFeatures())
	fmt.Printf("   Good for: Production deployment with full observability\n")

	// Show enterprise features in action (with graceful fallbacks)
	server.LogInfo("Production server initialized")
	fmt.Printf("   ✓ All enterprise features available\n")
}

func showCustomConfig() {
	// Create custom configuration with only specific features
	cfg := &config.ServerConfig{
		Name:    "custom-app",
		Version: "1.0.0",

		// Only enable logging and security - no auth, cache, or telemetry
		Logging: &config.LoggingConfig{
			Enabled: true,
			Config: &logging.LoggerConfig{
				Name:      "custom-logger",
				Level:     logging.LogLevelInfo,
				Formatter: "json",
			},
		},

		Security: &config.SecurityConfig{
			Enabled: true,
			Config: &security.ValidatorConfig{
				Enabled:    true,
				StrictMode: true,
			},
		},

		// Auth, Cache, Telemetry are nil (disabled)
	}

	server, err := gomcp.NewEnterpriseServer(cfg)
	if err != nil {
		log.Printf("   ⚠ Failed to create server: %v", err)
		return
	}
	defer server.Shutdown(context.Background())

	fmt.Printf("   Server: %s v%s\n", cfg.Name, cfg.Version)
	fmt.Printf("   Features: %v\n", server.GetEnabledFeatures())
	fmt.Printf("   Good for: Specific use cases requiring only certain features\n")

	// Show feature-specific usage
	if server.IsFeatureEnabled("security") {
		fmt.Printf("   ✓ Security validation enabled\n")
	}
	if !server.IsFeatureEnabled("authentication") {
		fmt.Printf("   ✓ Authentication disabled (no auth overhead)\n")
	}
}

// Example of how to handle optional features in your application code
func exampleOptionalFeatureUsage() {
	server := gomcp.NewMinimalServer("example", "1.0.0")

	// Safe way to use enterprise features - always check if they're available

	// Logging - always works (falls back to standard log)
	server.LogInfo("This always works", logging.String("component", "example"))

	// Caching - gracefully handles when disabled
	ctx := context.Background()
	_, err := server.GetFromCache(ctx, "some-key")
	if err == cache.ErrCacheMiss {
		// Expected when caching is disabled
		fmt.Println("Cache miss (caching disabled)")
	}

	// Setting cache always succeeds (no-op if disabled)
	server.SetInCache(ctx, "key", "value") // Silently succeeds

	// Security validation - always works (passes through if disabled)
	input := map[string]interface{}{"data": "user input"}
	result, _ := server.ValidateInput(ctx, input)
	if result.Valid {
		fmt.Println("Input is valid (or security is disabled)")
	}

	// Feature checking
	if server.IsFeatureEnabled("authentication") {
		// Only run auth-specific code if auth is enabled
		authManager := server.Auth()
		if authManager != nil {
			// Use authentication
		}
	}
}

// Example showing gradual migration to enterprise features
func exampleGradualMigration() {
	fmt.Println("\n=== GRADUAL MIGRATION EXAMPLE ===")
	fmt.Println("Start minimal, add features as needed:")
	fmt.Println()

	fmt.Println("Step 1: Start with minimal server")
	fmt.Println("   - No dependencies")
	fmt.Println("   - Core MCP functionality")
	fmt.Println("   - Easy to deploy anywhere")
	fmt.Println()

	fmt.Println("Step 2: Add logging when you need observability")
	fmt.Println("   - Add structured logging")
	fmt.Println("   - Better debugging and monitoring")
	fmt.Println("   - Still lightweight")
	fmt.Println()

	fmt.Println("Step 3: Add caching when performance matters")
	fmt.Println("   - Improve response times")
	fmt.Println("   - Reduce computational overhead")
	fmt.Println("   - Memory-efficient LRU cache")
	fmt.Println()

	fmt.Println("Step 4: Add security when handling untrusted input")
	fmt.Println("   - Input validation and sanitization")
	fmt.Println("   - Protection against common attacks")
	fmt.Println("   - Configurable security policies")
	fmt.Println()

	fmt.Println("Step 5: Add authentication when access control is needed")
	fmt.Println("   - JWT, OAuth2, API key support")
	fmt.Println("   - Role-based access control (RBAC)")
	fmt.Println("   - Fine-grained permissions")
	fmt.Println()

	fmt.Println("Step 6: Add telemetry for production observability")
	fmt.Println("   - Distributed tracing")
	fmt.Println("   - Performance monitoring")
	fmt.Println("   - Integration with observability platforms")
}
