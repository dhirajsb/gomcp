# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Development
- `go run examples/simple/main.go` - Run simple MCP server example
- `go run examples/typed/main.go` - Run typed parameters example
- `go run examples/http/main.go` - Run HTTP server example
- `go build` - Build the library
- `go test ./...` - Run all tests
- `go test -v ./...` - Run tests with verbose output
- `go mod tidy` - Clean up dependencies
- `go mod download` - Download dependencies

### Code Quality
- `go fmt ./...` - Format all Go code
- `go vet ./...` - Run Go vet for static analysis
- `golint ./...` - Run golint (if available)

## Architecture

This is a Go library for building MCP (Model Context Protocol) servers. The library provides:

### Core Components
- **types/**: MCP protocol types and JSON-RPC message definitions
- **transport/**: Transport implementations (stdio, SSE, streamable HTTP)
- **server/**: Core MCP server implementation with handler management
- **examples/**: Sample implementations demonstrating different usage patterns

### Key Features
- **Multiple Transports**: Supports stdio, Server-Sent Events (SSE), and Streamable HTTP
- **Function-based Handlers**: Register regular Go functions as tools, resources, and prompts
- **Type Safety**: Automatic schema generation from Go function signatures
- **Validation**: Built-in parameter validation using validator/v10
- **Easy API**: Quick builder pattern for rapid development

### Transport Support
- **Stdio**: For local MCP servers (default for Claude Desktop)
- **SSE**: For web-based deployments (legacy)
- **Streamable HTTP**: For modern web deployments (recommended)

### Usage Patterns
1. **Simple Functions**: `server.RegisterTool("name", functionName)`
2. **Typed Parameters**: Use structs with validation tags for complex parameters
3. **Quick API**: `gomcp.Quick().Tool("name", fn).Run()` for rapid prototyping

### Examples
- `examples/simple/`: Basic function registration
- `examples/typed/`: Structured parameters with validation
- `examples/http/`: HTTP server with multiple transports