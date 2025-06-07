package gomcp

import (
	"github.com/dhirajsb/gomcp/server"
	"github.com/dhirajsb/gomcp/transport"
)

// NewServer creates a new MCP server
func NewServer() *server.Server {
	return server.NewServer("Go MCP Server", "1.0.0")
}

// Transport constructors

// Stdio creates a stdio transport
func Stdio() transport.Transport {
	return transport.NewStdioTransport(transport.StdioConfig{})
}

// SSE creates an SSE transport
func SSE(host string, port int) transport.Transport {
	return transport.NewSSETransport(transport.HTTPConfig{
		Host: host,
		Port: port,
	})
}

// StreamableHTTP creates a streamable HTTP transport
func StreamableHTTP(host string, port int) transport.Transport {
	return transport.NewStreamableHTTPTransport(transport.HTTPConfig{
		Host: host,
		Port: port,
	})
}

// Quick API for rapid development

// Quick returns a builder for quick server setup
func Quick() *QuickBuilder {
	return &QuickBuilder{
		server: NewServer(),
	}
}

type QuickBuilder struct {
	server *server.Server
}

// Tool registers a tool
func (qb *QuickBuilder) Tool(name string, fn interface{}) *QuickBuilder {
	qb.server.RegisterTool(name, fn)
	return qb
}

// Resource registers a resource
func (qb *QuickBuilder) Resource(name string, fn interface{}) *QuickBuilder {
	qb.server.RegisterResource(name, fn)
	return qb
}

// Prompt registers a prompt
func (qb *QuickBuilder) Prompt(name string, fn interface{}) *QuickBuilder {
	qb.server.RegisterPrompt(name, fn)
	return qb
}

// Run starts the server with stdio transport
func (qb *QuickBuilder) Run() error {
	return qb.server.Start(Stdio())
}

// RunSSE starts the server with SSE transport
func (qb *QuickBuilder) RunSSE(host string, port int) error {
	return qb.server.Start(SSE(host, port))
}

// RunHTTP starts the server with streamable HTTP transport
func (qb *QuickBuilder) RunHTTP(host string, port int) error {
	return qb.server.Start(StreamableHTTP(host, port))
}
