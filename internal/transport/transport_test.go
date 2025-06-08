package transport

import (
	"testing"
	"time"
)

func TestStdioTransport(t *testing.T) {
	// Create stdio transport
	config := StdioConfig{}
	transport := NewStdioTransport(config)

	if transport.Type() != TransportStdio {
		t.Errorf("Expected transport type '%s', got '%s'", TransportStdio, transport.Type())
	}

	// Test Listen (should succeed for stdio)
	err := transport.Listen()
	if err != nil {
		t.Errorf("Stdio Listen should not fail: %v", err)
	}

	// Test Accept (should return a connection)
	conn, err := transport.Accept()
	if err != nil {
		t.Errorf("Stdio Accept failed: %v", err)
	}

	if conn == nil {
		t.Error("Expected non-nil connection")
	}

	if conn.RemoteAddr() != "stdio" {
		t.Errorf("Expected remote addr 'stdio', got '%s'", conn.RemoteAddr())
	}

	// Test connection context
	ctx := conn.Context()
	if ctx == nil {
		t.Error("Expected non-nil context")
	}

	// Test Close
	err = transport.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestSSETransport(t *testing.T) {
	// Create SSE transport with test config
	config := HTTPConfig{
		Host: "localhost",
		Port: 0, // Use random port
		Path: "/test-sse",
	}
	transport := NewSSETransport(config)

	if transport.Type() != TransportSSE {
		t.Errorf("Expected transport type '%s', got '%s'", TransportSSE, transport.Type())
	}

	// Test Listen
	err := transport.Listen()
	if err != nil {
		t.Errorf("SSE Listen failed: %v", err)
	}

	// Test Close
	err = transport.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestStreamableHTTPTransport(t *testing.T) {
	// Create HTTP transport with test config
	config := HTTPConfig{
		Host: "localhost",
		Port: 0, // Use random port
		Path: "/test-http",
	}
	transport := NewStreamableHTTPTransport(config)

	if transport.Type() != TransportStreamableHTTP {
		t.Errorf("Expected transport type '%s', got '%s'", TransportStreamableHTTP, transport.Type())
	}

	// Test Listen
	err := transport.Listen()
	if err != nil {
		t.Errorf("HTTP Listen failed: %v", err)
	}

	// Test Close
	err = transport.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

func TestStdioConnection(t *testing.T) {
	config := StdioConfig{}
	transport := NewStdioTransport(config)
	transport.Listen()

	conn, err := transport.Accept()
	if err != nil {
		t.Fatalf("Failed to get connection: %v", err)
	}

	// Test Write
	testData := []byte("test message")
	err = conn.Write(testData)
	if err != nil {
		t.Errorf("Write failed: %v", err)
	}

	// Test Close
	err = conn.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Test Write after close (should fail)
	err = conn.Write(testData)
	if err == nil {
		t.Error("Expected write to fail after close")
	}
}

func TestTransportAcceptTimeout(t *testing.T) {
	// Test SSE transport accept timeout
	config := HTTPConfig{
		Host: "localhost",
		Port: 0,
		Path: "/timeout-test",
	}
	transport := NewSSETransport(config)
	transport.Listen()

	// Accept should timeout since no client connects
	start := time.Now()
	_, err := transport.Accept()
	duration := time.Since(start)

	if err == nil {
		t.Error("Expected timeout error")
	}

	// Should timeout around 30 seconds (with some tolerance)
	if duration < 25*time.Second || duration > 35*time.Second {
		t.Errorf("Expected timeout around 30s, got %v", duration)
	}

	transport.Close()
}

func TestHTTPConfigDefaults(t *testing.T) {
	// Test SSE with empty config
	sseTransport := NewSSETransport(HTTPConfig{})
	sseConfig := sseTransport.config

	if sseConfig.Host != "localhost" {
		t.Errorf("Expected default host 'localhost', got '%s'", sseConfig.Host)
	}

	if sseConfig.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", sseConfig.Port)
	}

	if sseConfig.Path != "/sse" {
		t.Errorf("Expected default path '/sse', got '%s'", sseConfig.Path)
	}

	// Test HTTP with empty config
	httpTransport := NewStreamableHTTPTransport(HTTPConfig{})
	httpConfig := httpTransport.config

	if httpConfig.Host != "localhost" {
		t.Errorf("Expected default host 'localhost', got '%s'", httpConfig.Host)
	}

	if httpConfig.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", httpConfig.Port)
	}

	if httpConfig.Path != "/mcp" {
		t.Errorf("Expected default path '/mcp', got '%s'", httpConfig.Path)
	}
}

func TestTransportConstants(t *testing.T) {
	expectedTypes := map[string]string{
		"stdio":           TransportStdio,
		"sse":             TransportSSE,
		"streamable-http": TransportStreamableHTTP,
		"websocket":       TransportWebSocket,
		"unix":            TransportUnixSocket,
	}

	for expected, constant := range expectedTypes {
		if constant != expected {
			t.Errorf("Expected transport type '%s', got '%s'", expected, constant)
		}
	}
}
