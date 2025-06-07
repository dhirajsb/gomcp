package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dhirajsb/gomcp/auth"
	"github.com/dhirajsb/gomcp/cache"
	"github.com/dhirajsb/gomcp/logging"
	"github.com/dhirajsb/gomcp/security"
	"github.com/dhirajsb/gomcp/server"
)

// Example demonstrating comprehensive performance metrics
func main() {
	fmt.Println("=== Go MCP Performance Metrics Demo ===")
	fmt.Println()

	// 1. Authentication & RBAC Metrics
	fmt.Println("1. Authentication & RBAC Metrics")
	fmt.Println("----------------------------------------")
	demoAuthMetrics()

	// 2. Security Validation Metrics
	fmt.Println("\n2. Security Validation Metrics")
	fmt.Println("----------------------------------------")
	demoSecurityMetrics()

	// 3. Cache Performance Metrics
	fmt.Println("\n3. Cache Performance Metrics")
	fmt.Println("----------------------------------------")
	demoCacheMetrics()

	// 4. Logging Metrics
	fmt.Println("\n4. Logging System Metrics")
	fmt.Println("----------------------------------------")
	demoLoggingMetrics()

	// 5. Server Request Metrics
	fmt.Println("\n5. MCP Server Request Metrics")
	fmt.Println("----------------------------------------")
	demoServerMetrics()

	fmt.Println("\n=== Metrics Demo Complete ===")
}

func demoAuthMetrics() {
	// Create RBAC and auth manager
	rbac := auth.NewInMemoryRBAC()
	authConfig := auth.AuthConfig{
		Provider: "test",
		Enabled:  true,
		Required: true,
	}
	authManager := auth.NewAuthManager(authConfig, rbac)

	// Simulate some authentication operations
	fmt.Println("Simulating authentication operations...")

	// Mock user for testing
	user := &auth.UserIdentity{
		ID:       "user123",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	// Simulate permission checks
	for i := 0; i < 5; i++ {
		// Simulate different permission checks
		rbac.HasPermission(user, "tools", "list", "*")
		rbac.HasPermission(user, "tools", "call", "calculator")
		rbac.HasPermission(user, "admin", "manage", "*") // This should fail
		time.Sleep(time.Millisecond)                     // Small delay to simulate processing
	}

	// Get and display auth metrics
	authMetrics := authManager.GetMetrics()
	rbacMetrics := rbac.GetMetrics()

	fmt.Printf("Auth Success Rate: %.2f%%\n", authMetrics["auth_success_rate"].(float64)*100)
	fmt.Printf("Permission Checks: %d\n", rbacMetrics["permission_checks"])
	fmt.Printf("Permission Grant Rate: %.2f%%\n", rbacMetrics["permission_grant_rate"].(float64)*100)
	fmt.Printf("Average Permission Check Latency: %.3f ms\n", rbacMetrics["avg_perm_latency_ms"])
}

func demoSecurityMetrics() {
	// Create security validator manager
	securityConfig := security.ValidatorConfig{
		Enabled:       true,
		StrictMode:    false,
		AutoSanitize:  true,
		MaxViolations: 10,
	}
	securityManager := security.NewSecurityValidatorManager(securityConfig)

	fmt.Println("Simulating security validation operations...")

	// Test various security threats

	// Clean input
	cleanInput := map[string]interface{}{
		"name":  "John Doe",
		"email": "john@example.com",
	}
	securityManager.ValidateInput(context.Background(), cleanInput)

	// SQL injection attempts
	sqlInput := map[string]interface{}{
		"query": "SELECT * FROM users WHERE id = 1; DROP TABLE users;",
		"name":  "Robert'; DROP TABLE students;--",
	}
	securityManager.ValidateInput(context.Background(), sqlInput)

	// XSS attempts
	xssInput := map[string]interface{}{
		"comment": "<script>alert('XSS')</script>",
		"html":    "<img src='x' onerror='alert(1)'>",
	}
	securityManager.ValidateInput(context.Background(), xssInput)

	// Path traversal attempts
	pathInput := map[string]interface{}{
		"file": "../../../etc/passwd",
		"path": "..\\..\\windows\\system32\\",
	}
	securityManager.ValidateInput(context.Background(), pathInput)

	// Get and display security metrics
	securityMetrics := securityManager.GetMetrics()
	validatorMetrics := securityManager.GetValidatorMetrics()

	fmt.Printf("Total Validations: %d\n", securityMetrics["validations_total"])
	fmt.Printf("Blocked Rate: %.2f%%\n", securityMetrics["block_rate"].(float64)*100)
	fmt.Printf("SQL Injection Blocks: %d\n", securityMetrics["sql_injection_blocked"])
	fmt.Printf("XSS Blocks: %d\n", securityMetrics["xss_blocked"])
	fmt.Printf("Path Traversal Blocks: %d\n", securityMetrics["path_traversal_blocked"])

	// Show validator-specific metrics
	if sqlMetrics, exists := validatorMetrics["sql_injection"]; exists {
		fmt.Printf("SQL Validator Avg Latency: %.3f ms\n", sqlMetrics.AvgLatency)
	}
}

func demoCacheMetrics() {
	// Create cache configuration
	cacheConfig := cache.CacheConfig{
		Name:           "demo-cache",
		Type:           "memory",
		Enabled:        true,
		DefaultTTL:     time.Minute * 5,
		MaxSize:        1000,
		MaxMemory:      1024 * 1024, // 1MB
		EvictionPolicy: "lru",
	}

	// Create memory cache
	memoryCache := cache.NewMemoryCache("demo-cache", cacheConfig)

	fmt.Println("Simulating cache operations...")

	// Perform cache operations
	for i := 0; i < 10; i++ {
		key := fmt.Sprintf("key-%d", i)
		value := fmt.Sprintf("value-%d", i)

		// Set values
		memoryCache.Set(context.Background(), key, value, time.Minute)

		// Get some values (mix of hits and misses)
		memoryCache.Get(context.Background(), key)
		memoryCache.Get(context.Background(), fmt.Sprintf("missing-key-%d", i)) // Cache miss
	}

	// Get cache statistics
	stats, _ := memoryCache.Stats(context.Background())

	fmt.Printf("Cache Hits: %d\n", stats.Hits)
	fmt.Printf("Cache Misses: %d\n", stats.Misses)
	fmt.Printf("Hit Ratio: %.2f%%\n", stats.HitRatio*100)
	fmt.Printf("Total Sets: %d\n", stats.Sets)
	fmt.Printf("Cache Size: %d items\n", stats.Size)
	fmt.Printf("Memory Usage: %d bytes\n", stats.Memory)
}

func demoLoggingMetrics() {
	// Create logger configuration
	logConfig := logging.LoggerConfig{
		Name:      "demo-logger",
		Level:     logging.LogLevelDebug,
		Async:     false,
		Formatter: "json",
	}

	// Create logger
	logger, err := logging.NewLogger(logConfig)
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}

	fmt.Println("Simulating logging operations...")

	// Generate various log entries
	logger.Debug("Debug message")
	logger.Info("Application started")
	logger.Warn("This is a warning")
	logger.Error("An error occurred")

	// Structured logging
	logger.WithFields(
		logging.String("user_id", "123"),
		logging.String("action", "login"),
	).Info("User logged in")

	logger.WithComponent("auth").
		WithUser("user456").
		Info("Authentication successful")

	// Get logging statistics
	stats := logger.GetStats()

	fmt.Printf("Total Log Entries: %d\n", stats.TotalEntries)
	fmt.Printf("Debug Entries: %d\n", stats.EntriesByLevel[logging.LogLevelDebug])
	fmt.Printf("Info Entries: %d\n", stats.EntriesByLevel[logging.LogLevelInfo])
	fmt.Printf("Warning Entries: %d\n", stats.EntriesByLevel[logging.LogLevelWarn])
	fmt.Printf("Error Entries: %d\n", stats.EntriesByLevel[logging.LogLevelError])
	fmt.Printf("Logger Uptime: %v\n", stats.Uptime)
}

func demoServerMetrics() {
	// Create MCP server
	srv := server.NewServer("metrics-demo", "1.0.0")

	// Register a simple tool
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
	srv.RegisterTool("calculator", calculator)

	fmt.Println("Simulating MCP server operations...")

	// Simulate some requests (this would normally come from transport)

	// Simulate tool calls through direct handler access
	for i := 0; i < 5; i++ {
		// This simulates the metrics recording that would happen in real requests
		srv.GetMetrics() // Initialize metrics

		// In a real scenario, these would be recorded by the handleMessage method
		time.Sleep(time.Millisecond) // Simulate processing time
	}

	// Get server metrics
	serverMetrics := srv.GetMetrics()
	methodMetrics := srv.GetMethodMetrics()
	connectionMetrics := srv.GetConnectionMetrics()

	fmt.Printf("Total Requests: %d\n", serverMetrics["requests_total"])
	fmt.Printf("Success Rate: %.2f%%\n", serverMetrics["success_rate"].(float64)*100)
	fmt.Printf("Tool Invocations: %d\n", serverMetrics["tool_invocations"])
	fmt.Printf("Active Connections: %d\n", connectionMetrics["active"])
	fmt.Printf("Server Uptime: %v\n", serverMetrics["uptime"])

	// Show method-specific metrics if any
	if len(methodMetrics) > 0 {
		fmt.Println("\nMethod-specific metrics:")
		for method, metrics := range methodMetrics {
			fmt.Printf("  %s: %d requests\n", method, metrics.Requests)
		}
	}
}

// Helper function to repeat string (Go doesn't have this built-in)
func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// Override string multiplication for demo formatting
var _ = func() interface{} {
	// This is just for the demo - normally you'd define this properly
	return nil
}()
