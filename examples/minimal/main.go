package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp/pkg/gomcp"
)

// Example demonstrating minimal MCP server usage
func main() {
	fmt.Println("=== Minimal Go MCP Server Example ===")

	// Create a minimal server
	server := gomcp.NewServer()

	// Register some simple tools
	server.RegisterTool("add", func(a, b int) int {
		return a + b
	})

	server.RegisterTool("greet", func(name string) string {
		if name == "" {
			return "Hello, World!"
		}
		return fmt.Sprintf("Hello, %s!", name)
	})

	fmt.Println("✓ Registered tools: add, greet")
	fmt.Println("Starting MCP server with stdio transport...")

	// Start the server with stdio transport
	if err := server.Start(gomcp.Stdio()); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}
