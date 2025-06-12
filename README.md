# GoMCP - Go Library for Model Context Protocol

[![Go Version](https://img.shields.io/github/go-mod/go-version/dhirajsb/gomcp?style=flat-square&logo=go)](https://go.dev/)
[![CI Status](https://img.shields.io/github/actions/workflow/status/dhirajsb/gomcp/ci.yml?branch=main&style=flat-square&logo=github&label=CI)](https://github.com/dhirajsb/gomcp/actions/workflows/ci.yml)
[![Code Coverage](https://img.shields.io/codecov/c/github/dhirajsb/gomcp?style=flat-square&logo=codecov)](https://codecov.io/gh/dhirajsb/gomcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/dhirajsb/gomcp?style=flat-square)](https://goreportcard.com/report/github.com/dhirajsb/gomcp)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4?style=flat-square&logo=go)](https://godoc.org/github.com/dhirajsb/gomcp)
[![License](https://img.shields.io/github/license/dhirajsb/gomcp?style=flat-square)](LICENSE)
[![Release](https://img.shields.io/github/v/release/dhirajsb/gomcp?style=flat-square&logo=github)](https://github.com/dhirajsb/gomcp/releases)
[![Security](https://img.shields.io/snyk/vulnerabilities/github/dhirajsb/gomcp?style=flat-square&logo=snyk)](https://snyk.io/test/github/dhirajsb/gomcp)

A powerful, type-safe Go library for building MCP (Model Context Protocol) servers with support for multiple transports and enterprise features.

## Features

- **Multiple Transports**: stdio, Server-Sent Events (SSE), and Streamable HTTP
- **Function-based Handlers**: Register regular Go functions as tools, resources, and prompts
- **Type Safety**: Automatic JSON schema generation from Go function signatures
- **Validation**: Built-in parameter validation using `validator/v10`
- **Easy APIs**: Both simple and advanced APIs for different use cases
- **Enterprise Ready**: Authentication, security, caching, and monitoring (planned)

## Quick Start

```go
package main

import (
    "context"
    "log"
    
    "github.com/dhirajsb/gomcp"
)

func main() {
    // Quick API - simplest way to get started
    err := gomcp.Quick().
        Tool("add", Add).
        Tool("search", SearchFiles).
        Resource("status", GetStatus).
        Prompt("greeting", GreetingPrompt).
        Run() // Starts with stdio transport
    
    log.Fatal(err)
}

func Add(ctx context.Context, a, b int) (int, error) {
    return a + b, nil
}

func SearchFiles(ctx context.Context, query, directory string) ([]string, error) {
    // Implementation
    return []string{"file1.go", "file2.go"}, nil
}

func GetStatus(ctx context.Context) (string, error) {
    return "Server is running", nil
}

func GreetingPrompt(ctx context.Context, name string) (string, error) {
    return fmt.Sprintf("Hello %s! How can I help you today?", name), nil
}
```

## Advanced Usage

### Structured Parameters with Validation

```go
type SearchParams struct {
    Query     string   `json:"query" validate:"required,min=1"`
    Directory string   `json:"directory,omitempty" validate:"omitempty,dir"`
    MaxFiles  int      `json:"maxFiles,omitempty" validate:"omitempty,min=1,max=1000"`
    FileTypes []string `json:"fileTypes,omitempty" validate:"dive,oneof=go js ts py"`
    Recursive bool     `json:"recursive,omitempty"`
}

type SearchResult struct {
    Files     []string `json:"files"`
    Count     int      `json:"count"`
    Truncated bool     `json:"truncated"`
}

func AdvancedSearch(ctx context.Context, params SearchParams) (SearchResult, error) {
    // Automatic validation of params based on struct tags
    // Implementation
    return SearchResult{}, nil
}

// Register with server
server.RegisterTool("advanced_search", AdvancedSearch)
```

### Multiple Transports

```go
// Stdio transport (default for Claude Desktop)
server.Start(gomcp.Stdio())

// Server-Sent Events
server.Start(gomcp.SSE("localhost", 8080))

// Streamable HTTP (recommended for web)
server.Start(gomcp.StreamableHTTP("localhost", 8080))
```

### Full Server Setup

```go
package main

import (
    "context"
    "log"
    
    "github.com/dhirajsb/gomcp"
)

func main() {
    server := gomcp.NewServer()
    
    // Register tools
    server.RegisterTool("calculate", Calculate)
    server.RegisterTool("search_files", SearchFiles)
    
    // Register resources
    server.RegisterResource("system_info", GetSystemInfo)
    server.RegisterResource("file_content", GetFileContent)
    
    // Register prompts
    server.RegisterPrompt("code_review", CodeReviewPrompt)
    server.RegisterPrompt("documentation", DocumentationPrompt)
    
    // Start with HTTP transport
    log.Fatal(server.Start(gomcp.StreamableHTTP("localhost", 8080)))
}
```

## Transport Support

### Stdio Transport
Perfect for local development and Claude Desktop integration:
```go
server.Start(gomcp.Stdio())
```

### Server-Sent Events (SSE)
For legacy web deployments:
```go
server.Start(gomcp.SSE("localhost", 8080))
```

### Streamable HTTP
Recommended for modern web deployments:
```go
server.Start(gomcp.StreamableHTTP("localhost", 8080))
```

## Examples

The `examples/` directory contains complete working examples:

- **`examples/simple/`**: Basic function registration
- **`examples/typed/`**: Structured parameters with validation
- **`examples/http/`**: HTTP server with web interface

Run examples:
```bash
# Simple example with stdio
go run examples/simple/main.go

# Typed parameters example
go run examples/typed/main.go

# HTTP server example
go run examples/http/main.go
```

## API Reference

### Quick API

```go
gomcp.Quick().
    Tool("name", function).          // Register tool
    Resource("name", function).      // Register resource
    Prompt("name", function).        // Register prompt
    Run()                           // Start with stdio

// Or specify transport
gomcp.Quick().Tool("add", Add).RunHTTP("localhost", 8080)
```

### Full API

```go
server := gomcp.NewServer()
server.RegisterTool("name", function)
server.RegisterResource("name", function)
server.RegisterPrompt("name", function)
server.Start(transport)
```

### Transport Constructors

```go
gomcp.Stdio()                              // Stdio transport
gomcp.SSE("host", port)                    // SSE transport
gomcp.StreamableHTTP("host", port)         // HTTP transport
```

## Function Signatures

The library supports various function signatures:

### Tools
```go
// Simple parameters
func Add(ctx context.Context, a, b int) (int, error)

// Struct parameters with validation
func Search(ctx context.Context, params SearchParams) (SearchResult, error)

// Multiple return values
func GetFileInfo(ctx context.Context, path string) (FileInfo, error)
```

### Resources
```go
// String resource
func GetConfig(ctx context.Context) (string, error)

// Structured resource
func GetStatus(ctx context.Context) (ServerStatus, error)

// Parameterized resource
func GetFile(ctx context.Context, path string) (string, error)
```

### Prompts
```go
// Simple prompt
func Greeting(ctx context.Context, name string) (string, error)

// Structured prompt with multiple messages
func CodeReview(ctx context.Context, params ReviewParams) (PromptResult, error)
```

## Validation

Use struct tags for automatic parameter validation:

```go
type Params struct {
    Name    string `json:"name" validate:"required,min=1,max=100"`
    Email   string `json:"email" validate:"required,email"`
    Age     int    `json:"age" validate:"min=0,max=120"`
    Tags    []string `json:"tags" validate:"dive,min=1"`
}
```

Supported validation tags:
- `required` - Field is required
- `min=N`, `max=N` - Minimum/maximum value or length
- `email`, `url`, `uuid` - Format validation
- `oneof=a b c` - Must be one of specified values
- `dive` - Validate array/slice elements

## Protocol Compliance

This library implements the Model Context Protocol specification:

- **JSON-RPC 2.0**: Full compliance with JSON-RPC message format
- **Standard Methods**: `initialize`, `tools/list`, `tools/call`, `resources/list`, `resources/read`, `prompts/list`, `prompts/get`
- **Capabilities**: Proper capability negotiation and feature detection
- **Error Handling**: Standard error codes and messages

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Configuration

### Minimal Configuration

For basic MCP server functionality with no enterprise features:

```go
server := gomcp.NewServer()
// Core functionality only - no logging, caching, security, etc.
```

### Development Configuration

Recommended setup for development with helpful debugging features:

```go
import "github.com/dhirajsb/gomcp/pkg/builder"

server := gomcp.NewBuilder().
    WithName("my-dev-server").
    WithVersion("1.0.0").
    
    // Development logging - text format, debug level
    WithLogger(gomcp.ConsoleLogger("dev-logger", "debug")).
    
    // Basic memory cache for development
    WithCache(gomcp.MemoryCache("dev-cache", 1000)). // 1000 items max
    
    // Simple telemetry to stdout
    WithTelemetry(gomcp.StdoutTelemetry("my-dev-server", "1.0.0")).
    
    Build()
```

### Production Configuration

Recommended setup for production with security, monitoring, and performance features:

```go
import "github.com/dhirajsb/gomcp/pkg/builder"

server := gomcp.NewBuilder().
    WithName("my-prod-server").
    WithVersion("1.0.0").
    
    // Production logging - JSON format, info level, async
    WithLogger(gomcp.JSONLogger("prod-logger", "info")).
    
    // Production-ready cache with LRU eviction
    WithCache(gomcp.MemoryCache("prod-cache", 10000)). // 10k items max
    
    // Security validation and sanitization
    WithSecurity(gomcp.StrictValidator("security-validator")).
    
    // Production metrics with Prometheus endpoint
    WithMetrics(gomcp.PrometheusMetricsWithHTTP("metrics", 9090, "/metrics")).
    
    // Distributed tracing to OTLP collector
    WithTelemetry(gomcp.OTLPTelemetry("my-prod-server", "1.0.0", "http://otel-collector:4318")).
    
    Build()
```

### Enterprise Configuration with Authentication

For production environments requiring authentication:

```go
import "github.com/dhirajsb/gomcp/pkg/builder"

server := gomcp.NewBuilder().
    WithName("secure-server").
    WithVersion("1.0.0").
    
    // JWT authentication with RBAC
    WithAuth(gomcp.JWTAuth("jwt-provider").
        WithJWTSecret("your-secret-key").
        WithRoleRequired("api-user")). // Require specific role
    
    // All production features
    WithLogger(gomcp.JSONLogger("prod-logger", "info")).
    WithCache(gomcp.MemoryCache("prod-cache", 10000)).
    WithSecurity(gomcp.StrictValidator("security")).
    WithMetrics(gomcp.PrometheusMetricsWithHTTP("metrics", 9090, "/metrics")).
    WithTelemetry(gomcp.OTLPTelemetry("secure-server", "1.0.0", "http://otel-collector:4318")).
    
    Build()
```

### Configuration Options Summary

| Feature | Development | Production | Enterprise |
|---------|-------------|------------|------------|
| **Logging** | Console/Debug | JSON/Info/Async | JSON/Info/Async |
| **Caching** | Memory/1K items | Memory/10K items | Memory/Redis |
| **Security** | Optional | Strict Validation | Strict + Auth |
| **Metrics** | Basic | Prometheus/HTTP | Prometheus/HTTP |
| **Telemetry** | Stdout | OTLP/Sampled | OTLP/Sampled |
| **Authentication** | None | Optional | JWT/RBAC Required |

### Environment-Specific Configuration

Use environment variables for deployment-specific settings:

```go
import "os"

var config struct {
    Environment string
    LogLevel    string
    CacheSize   int
    MetricsPort int
}

config.Environment = getEnv("ENVIRONMENT", "development")
config.LogLevel = getEnv("LOG_LEVEL", "info")
config.CacheSize = getEnvInt("CACHE_SIZE", 1000)
config.MetricsPort = getEnvInt("METRICS_PORT", 9090)

server := gomcp.NewBuilder().
    WithName("my-server").
    WithVersion("1.0.0").
    WithLogger(gomcp.JSONLogger("logger", config.LogLevel)).
    WithCache(gomcp.MemoryCache("cache", config.CacheSize)).
    WithMetrics(gomcp.PrometheusMetricsWithHTTP("metrics", config.MetricsPort, "/metrics")).
    Build()

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}
```

## Roadmap

- [x] Core MCP protocol implementation
- [x] Multiple transport support (stdio, SSE, HTTP)
- [x] Function-based handlers
- [x] Type safety and validation
- [x] Authentication and authorization (JWT/RBAC)
- [x] Security validation and sanitization
- [x] Caching with LRU eviction
- [x] Comprehensive logging and metrics (Prometheus)
- [x] Distributed tracing (OpenTelemetry)
- [ ] Middleware support
- [ ] WebSocket transport
- [ ] Client implementation