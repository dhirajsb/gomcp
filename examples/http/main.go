package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/dhirajsb/gomcp/pkg/gomcp"
)

func main() {
	server := gomcp.NewServer()

	// Register some demo tools
	server.RegisterTool("echo", Echo)
	server.RegisterTool("time", GetCurrentTime)
	server.RegisterTool("delay", DelayedResponse)

	// Register demo resources
	server.RegisterResource("server_status", GetServerStatus)

	// Register demo prompts
	server.RegisterPrompt("greeting", GreetingPrompt)

	// Start server with streamable HTTP transport
	log.Printf("Starting MCP server on http://localhost:8080/mcp")
	log.Fatal(server.Start(gomcp.StreamableHTTP("localhost", 8080)))
}

// Echo returns the input message
func Echo(ctx context.Context, message string) (string, error) {
	return fmt.Sprintf("Echo: %s", message), nil
}

// GetCurrentTime returns the current time
func GetCurrentTime(ctx context.Context) (string, error) {
	return time.Now().Format(time.RFC3339), nil
}

// DelayedResponse simulates a long-running operation
func DelayedResponse(ctx context.Context, seconds int, message string) (string, error) {
	if seconds < 0 || seconds > 30 {
		return "", fmt.Errorf("delay must be between 0 and 30 seconds")
	}

	select {
	case <-time.After(time.Duration(seconds) * time.Second):
		return fmt.Sprintf("Delayed response after %d seconds: %s", seconds, message), nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

type ServerStatus struct {
	Status    string    `json:"status"`
	Uptime    string    `json:"uptime"`
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
}

var startTime = time.Now()

func GetServerStatus(ctx context.Context) (ServerStatus, error) {
	uptime := time.Since(startTime)

	return ServerStatus{
		Status:    "running",
		Uptime:    uptime.String(),
		Timestamp: time.Now(),
		Version:   "1.0.0",
	}, nil
}

// GreetingPrompt generates a personalized greeting
func GreetingPrompt(ctx context.Context, name, style string) (string, error) {
	if name == "" {
		name = "there"
	}

	switch style {
	case "formal":
		return fmt.Sprintf("Good day, %s. How may I assist you today?", name), nil
	case "casual":
		return fmt.Sprintf("Hey %s! What's up?", name), nil
	case "professional":
		return fmt.Sprintf("Hello %s, I'm here to help you with your questions.", name), nil
	default:
		return fmt.Sprintf("Hello %s! How can I help you today?", name), nil
	}
}
