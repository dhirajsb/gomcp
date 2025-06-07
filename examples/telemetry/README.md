# OpenTelemetry Integration Demo

This example demonstrates comprehensive OpenTelemetry integration with the Go MCP library, showing how to implement distributed tracing across all enterprise features.

## Features Demonstrated

### 1. Tracer Configuration
- Multiple exporter types (Jaeger, OTLP, stdout)
- Environment-specific configurations
- Sampling strategies
- Resource attributes and metadata

### 2. Distributed Tracing Coverage
- **Authentication & RBAC**: Trace auth flows and permission checks
- **Security Validation**: Track security scanning and threat detection
- **Caching Operations**: Monitor cache hits, misses, and evictions
- **MCP Server Requests**: End-to-end request tracing
- **Tool Invocations**: Detailed tool execution tracking

### 3. Observability Integration
- Jaeger for distributed tracing
- OpenTelemetry Collector pipeline
- Cloud provider integrations (AWS X-Ray, Google Cloud Trace, Azure Monitor)
- Commercial platforms (Datadog, New Relic, Honeycomb)

## Running the Demo

```bash
# Run the telemetry demonstration
go run examples/telemetry/main.go
```

## Configuration Examples

### Development Environment
```go
config := telemetry.TracerConfig{
    ServiceName:     "gomcp-dev",
    ServiceVersion:  "dev",
    Environment:     "development",
    Enabled:         true,
    SamplingRatio:   1.0, // Sample everything
    ExporterType:    "jaeger",
    JaegerEndpoint:  "http://localhost:14268/api/traces",
}
```

### Production Environment
```go
config := telemetry.TracerConfig{
    ServiceName:     "gomcp-production",
    ServiceVersion:  "1.0.0",
    Environment:     "production",
    Enabled:         true,
    SamplingRatio:   0.1, // Sample 10%
    ExporterType:    "otlp",
    OTLPEndpoint:    "http://otel-collector:4318",
    Headers: map[string]string{
        "Authorization": "Bearer <token>",
    },
}
```

## Integration with Components

### Authentication Manager
```go
authManager := auth.NewAuthManager(authConfig, rbac)
authManager.SetTracer(tracer)

// Authentication requests will now generate spans like:
// - auth.authenticate_request
// - rbac.has_permission
```

### Security Validation
```go
securityManager := security.NewSecurityValidatorManager(securityConfig)
securityManager.SetTracer(tracer)

// Security validation will generate spans like:
// - security.validate_input
// - security.validator.sql_injection
// - security.validator.xss
```

### Cache Operations
```go
cache := cache.NewMemoryCache("app-cache", cacheConfig)
cache.SetTracer(tracer)

// Cache operations will generate spans like:
// - cache.get
// - cache.set
// - cache.delete
```

### MCP Server
```go
server := server.NewServer("my-server", "1.0.0")
server.SetTracer(tracer)

// MCP requests will generate spans like:
// - mcp.handle_message
// - mcp.tools.call
// - mcp.resources.read
```

## Trace Attributes

The library automatically adds comprehensive attributes to spans:

### Authentication Spans
- `auth.provider`: Authentication provider type
- `auth.enabled`: Whether authentication is enabled
- `auth.required`: Whether authentication is required
- `user.id`: Authenticated user ID
- `user.name`: Username
- `auth.roles`: User roles

### Security Spans
- `security.validator_type`: Type of validator (sql_injection, xss, etc.)
- `security.blocked`: Whether input was blocked
- `security.threat_level`: Severity of detected threats
- `security.violations_count`: Number of violations found

### Cache Spans
- `cache.name`: Cache instance name
- `cache.type`: Cache type (memory, redis, etc.)
- `cache.hit`: Whether operation was a cache hit
- `cache.key`: Cache key
- `cache.size_bytes`: Item size

### MCP Server Spans
- `mcp.method`: MCP method name
- `mcp.tool_name`: Tool being invoked
- `mcp.success`: Whether request succeeded
- `mcp.latency_ms`: Request latency

## Benefits of Distributed Tracing

### 1. Performance Analysis
- Identify bottlenecks across components
- Track request latency distribution
- Monitor cache performance impact
- Analyze authentication overhead

### 2. Error Tracking
- Trace error propagation across services
- Correlate security violations with user actions
- Track failed authentication attempts
- Monitor tool execution failures

### 3. Security Monitoring
- Correlate security events across requests
- Track threat patterns and sources
- Monitor authentication flow anomalies
- Analyze cache-based attacks

### 4. Operational Insights
- Service dependency mapping
- Request flow visualization
- Capacity planning data
- SLA monitoring and alerting

## Best Practices

### 1. Sampling Strategy
- Use high sampling (100%) in development
- Use lower sampling (10-20%) in production
- Implement adaptive sampling for high-traffic services
- Sample security events at higher rates

### 2. Span Naming
- Use consistent naming conventions
- Include component and operation
- Make spans filterable and searchable
- Follow OpenTelemetry semantic conventions

### 3. Attribute Management
- Add meaningful business context
- Avoid high-cardinality attributes
- Include error details and codes
- Tag with environment and version info

### 4. Performance Considerations
- Use batching for span export
- Configure appropriate timeouts
- Monitor telemetry overhead
- Implement circuit breakers for exporters

## Troubleshooting

### Common Issues

1. **No traces appearing**
   - Check exporter configuration
   - Verify sampling settings
   - Confirm tracer initialization

2. **High latency**
   - Adjust batch settings
   - Use asynchronous export
   - Optimize attribute collection

3. **Missing spans**
   - Ensure context propagation
   - Check tracer setup in components
   - Verify span lifecycle management

### Debug Configuration
```go
config := telemetry.TracerConfig{
    ExporterType: "stdout", // See traces in console
    SamplingRatio: 1.0,     // Sample everything
}
```

## Integration Examples

See the `examples/telemetry/main.go` file for complete integration examples with different observability platforms and configuration patterns.