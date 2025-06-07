package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp"
	"github.com/dhirajsb/gomcp/transport"
)

// Example demonstrating minimal MCP server usage without any enterprise features
func main() {
	fmt.Println("=== Minimal Go MCP Server Example ===")
	fmt.Println()

	// Create a minimal server with only core functionality
	// No authentication, security, caching, logging, or telemetry
	server := gomcp.NewMinimalServer("minimal-server", "1.0.0")

	fmt.Printf("Created server: %s v%s\n", server.GetConfig().Name, server.GetConfig().Version)
	fmt.Printf("Enterprise features enabled: %v\n", server.GetEnabledFeatures())
	fmt.Println()

	// Register some simple tools
	fmt.Println("Registering tools...")

	// Calculator tool
	calculator := func(operation string, a, b float64) float64 {
		switch operation {
		case "add":
			return a + b
		case "subtract":
			return a - b
		case "multiply":
			return a * b
		case "divide":
			if b != 0 {
				return a / b
			}
			return 0
		default:
			return 0
		}
	}

	if err := server.RegisterTool("calculator", calculator); err != nil {
		log.Fatalf("Failed to register calculator tool: %v", err)
	}

	// Greeting tool
	greet := func(name string) string {
		if name == "" {
			return "Hello, World!"
		}
		return fmt.Sprintf("Hello, %s!", name)
	}

	if err := server.RegisterTool("greet", greet); err != nil {
		log.Fatalf("Failed to register greet tool: %v", err)
	}

	// Echo tool
	echo := func(message string) string {
		return message
	}

	if err := server.RegisterTool("echo", echo); err != nil {
		log.Fatalf("Failed to register echo tool: %v", err)
	}

	fmt.Println("✓ Registered calculator, greet, and echo tools")
	fmt.Println()

	// Register a simple resource
	fmt.Println("Registering resources...")

	// Server info resource
	serverInfo := func() map[string]interface{} {
		return map[string]interface{}{
			"name":     server.GetConfig().Name,
			"version":  server.GetConfig().Version,
			"features": server.GetEnabledFeatures(),
		}
	}

	if err := server.RegisterResource("server-info", serverInfo); err != nil {
		log.Fatalf("Failed to register server-info resource: %v", err)
	}

	fmt.Println("✓ Registered server-info resource")
	fmt.Println()

	// Register a simple prompt
	fmt.Println("Registering prompts...")

	// Code review prompt
	codeReview := func(code string, language string) string {
		if language == "" {
			language = "unknown"
		}
		return fmt.Sprintf("Please review this %s code:\n\n%s\n\nProvide feedback on code quality, potential issues, and suggestions for improvement.", language, code)
	}

	if err := server.RegisterPrompt("code-review", codeReview); err != nil {
		log.Fatalf("Failed to register code-review prompt: %v", err)
	}

	fmt.Println("✓ Registered code-review prompt")
	fmt.Println()

	// Create stdio transport (standard input/output)
	stdioTransport := transport.NewStdioTransport(transport.StdioConfig{})

	fmt.Println("Starting MCP server with stdio transport...")
	fmt.Println("Server is ready to accept MCP requests via stdin/stdout")
	fmt.Println("No enterprise features are active - this is pure core MCP functionality")
	fmt.Println()
	fmt.Println("Available tools: calculator, greet, echo")
	fmt.Println("Available resources: server-info")
	fmt.Println("Available prompts: code-review")
	fmt.Println()
	fmt.Println("Send MCP messages via stdin to interact with the server.")
	fmt.Println("Press Ctrl+C to exit.")
	fmt.Println()

	// Start the server (this will block)
	if err := server.Start(stdioTransport); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
