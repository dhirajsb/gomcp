package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp/pkg/builder"
	"github.com/dhirajsb/gomcp/pkg/features"
	"github.com/dhirajsb/gomcp/pkg/gomcp"
)

// Example of a user creating their own feature implementation
// by depending only on public interfaces from pkg/features

// CustomLogger implements the features.Logger interface
type CustomLogger struct {
	name   string
	prefix string
}

func NewCustomLogger(name, prefix string) features.Logger {
	return &CustomLogger{
		name:   name,
		prefix: prefix,
	}
}

func (cl *CustomLogger) Name() string {
	return cl.name
}

func (cl *CustomLogger) Log(level interface{}, message string, fields map[string]interface{}) {
	fmt.Printf("[%s] %v - %s: %s\n", cl.prefix, level, cl.name, message)
}

func (cl *CustomLogger) Close() error {
	fmt.Printf("[%s] Logger %s closed\n", cl.prefix, cl.name)
	return nil
}

func main() {
	fmt.Println("=== Custom Implementation Example ===")
	fmt.Println("This shows how users can create their own feature implementations")
	fmt.Println("using only the public interfaces from pkg/features")
	fmt.Println()

	// Create server with built-in features
	server, err := gomcp.NewBuilder("custom-impl-server", "1.0.0").
		WithLogger(builder.ConsoleLogger("builtin", "info")). // Built-in implementation
		WithLogger(NewCustomLogger("custom", "CUSTOM")).      // User's custom implementation
		WithCache(builder.SmallCache("cache")).
		Build()

	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}

	fmt.Printf("Built server with %d loggers\n", len(server.GetLoggers()))

	// Test both loggers
	for _, logger := range server.GetLoggers() {
		logger.Log("INFO", "Testing logger implementation", map[string]interface{}{
			"type": "test",
		})
	}

	fmt.Println()
	fmt.Println("✓ Successfully used both built-in and custom implementations!")
	fmt.Println("✓ User implementation depends only on public pkg/features interfaces")

	// Clean shutdown
	server.Close()
}
