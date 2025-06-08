package transport

import (
	"context"
	"io"
)

// Transport defines the interface for MCP transport mechanisms
type Transport interface {
	// Listen starts listening for connections
	Listen() error

	// Accept accepts a new connection
	Accept() (Connection, error)

	// Close closes the transport
	Close() error

	// Type returns the transport type
	Type() string
}

// Connection represents a transport connection
type Connection interface {
	// Read reads a message from the connection
	Read() ([]byte, error)

	// Write writes a message to the connection
	Write(data []byte) error

	// Close closes the connection
	Close() error

	// Context returns the connection context
	Context() context.Context

	// RemoteAddr returns the remote address (if applicable)
	RemoteAddr() string
}

// TransportConfig holds transport configuration
type TransportConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config"`
}

// StdioConfig for stdio transport
type StdioConfig struct {
	Reader io.Reader
	Writer io.Writer
}

// HTTPConfig for HTTP-based transports
type HTTPConfig struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	Path string `json:"path"`
	TLS  bool   `json:"tls"`
}

// Transport types
const (
	TransportStdio          = "stdio"
	TransportSSE            = "sse"
	TransportStreamableHTTP = "streamable-http"
	TransportWebSocket      = "websocket"
	TransportUnixSocket     = "unix"
)
