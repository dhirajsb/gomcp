package telemetry

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.17.0"
	"go.opentelemetry.io/otel/trace"
)

// TracerConfig holds OpenTelemetry tracer configuration
type TracerConfig struct {
	ServiceName    string            `json:"service_name"`
	ServiceVersion string            `json:"service_version"`
	Environment    string            `json:"environment"`
	Enabled        bool              `json:"enabled"`
	SamplingRatio  float64           `json:"sampling_ratio"`  // 0.0 to 1.0
	ExporterType   string            `json:"exporter_type"`   // "jaeger", "otlp", "stdout", "noop"
	JaegerEndpoint string            `json:"jaeger_endpoint"` // e.g., "http://localhost:14268/api/traces"
	OTLPEndpoint   string            `json:"otlp_endpoint"`   // e.g., "http://localhost:4318"
	Headers        map[string]string `json:"headers"`         // Additional headers for exporters
	BatchTimeout   time.Duration     `json:"batch_timeout"`   // Batch export timeout
	BatchSize      int               `json:"batch_size"`      // Maximum batch size
	ExportTimeout  time.Duration     `json:"export_timeout"`  // Individual export timeout
	Attributes     map[string]string `json:"attributes"`      // Custom resource attributes
}

// DefaultTracerConfig returns a default tracer configuration
func DefaultTracerConfig() TracerConfig {
	return TracerConfig{
		ServiceName:    "gomcp",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		Enabled:        true,
		SamplingRatio:  1.0, // Sample all traces in development
		ExporterType:   "stdout",
		BatchTimeout:   5 * time.Second,
		BatchSize:      512,
		ExportTimeout:  30 * time.Second,
		Headers:        make(map[string]string),
		Attributes:     make(map[string]string),
	}
}

// TracerManager manages OpenTelemetry tracing setup and cleanup
type TracerManager struct {
	config   TracerConfig
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// NewTracerManager creates a new tracer manager
func NewTracerManager(config TracerConfig) *TracerManager {
	return &TracerManager{
		config: config,
	}
}

// Initialize sets up OpenTelemetry tracing
func (tm *TracerManager) Initialize(ctx context.Context) error {
	if !tm.config.Enabled {
		// Set noop tracer provider
		otel.SetTracerProvider(trace.NewNoopTracerProvider())
		tm.tracer = otel.Tracer(tm.config.ServiceName)
		return nil
	}

	// Create resource
	res, err := tm.createResource()
	if err != nil {
		return fmt.Errorf("failed to create resource: %w", err)
	}

	// Create span exporter
	exporter, err := tm.createExporter(ctx)
	if err != nil {
		return fmt.Errorf("failed to create exporter: %w", err)
	}

	// Create batch span processor
	bsp := sdktrace.NewBatchSpanProcessor(
		exporter,
		sdktrace.WithBatchTimeout(tm.config.BatchTimeout),
		sdktrace.WithMaxExportBatchSize(tm.config.BatchSize),
		sdktrace.WithExportTimeout(tm.config.ExportTimeout),
	)

	// Create sampler
	sampler := sdktrace.AlwaysSample()
	if tm.config.SamplingRatio < 1.0 {
		sampler = sdktrace.TraceIDRatioBased(tm.config.SamplingRatio)
	}

	// Create tracer provider
	tm.provider = sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
		sdktrace.WithSampler(sampler),
	)

	// Set global tracer provider
	otel.SetTracerProvider(tm.provider)

	// Set global propagator for distributed tracing
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// Create tracer
	tm.tracer = otel.Tracer(
		tm.config.ServiceName,
		trace.WithInstrumentationVersion(tm.config.ServiceVersion),
	)

	log.Printf("OpenTelemetry tracer initialized with %s exporter", tm.config.ExporterType)
	return nil
}

// Shutdown gracefully shuts down the tracer provider
func (tm *TracerManager) Shutdown(ctx context.Context) error {
	if tm.provider != nil {
		return tm.provider.Shutdown(ctx)
	}
	return nil
}

// GetTracer returns the configured tracer
func (tm *TracerManager) GetTracer() trace.Tracer {
	return tm.tracer
}

// createResource creates the OpenTelemetry resource
func (tm *TracerManager) createResource() (*resource.Resource, error) {
	attributes := []attribute.KeyValue{
		semconv.ServiceName(tm.config.ServiceName),
		semconv.ServiceVersion(tm.config.ServiceVersion),
		attribute.String("environment", tm.config.Environment),
	}

	// Add custom attributes
	for key, value := range tm.config.Attributes {
		attributes = append(attributes, attribute.String(key, value))
	}

	// Add host information
	if hostname, err := os.Hostname(); err == nil {
		attributes = append(attributes, semconv.HostName(hostname))
	}

	return resource.NewWithAttributes(
		semconv.SchemaURL,
		attributes...,
	), nil
}

// createExporter creates the appropriate span exporter based on configuration
func (tm *TracerManager) createExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	switch tm.config.ExporterType {
	case "jaeger":
		return tm.createJaegerExporter()
	case "otlp":
		return tm.createOTLPExporter(ctx)
	case "stdout":
		return tm.createStdoutExporter()
	case "noop":
		return &noopExporter{}, nil
	default:
		return nil, fmt.Errorf("unsupported exporter type: %s", tm.config.ExporterType)
	}
}

// createJaegerExporter creates a Jaeger exporter
func (tm *TracerManager) createJaegerExporter() (sdktrace.SpanExporter, error) {
	endpoint := tm.config.JaegerEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:14268/api/traces"
	}

	return jaeger.New(jaeger.WithCollectorEndpoint(jaeger.WithEndpoint(endpoint)))
}

// createOTLPExporter creates an OTLP HTTP exporter
func (tm *TracerManager) createOTLPExporter(ctx context.Context) (sdktrace.SpanExporter, error) {
	endpoint := tm.config.OTLPEndpoint
	if endpoint == "" {
		endpoint = "http://localhost:4318"
	}

	options := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpoint),
		otlptracehttp.WithInsecure(), // Use HTTP instead of HTTPS by default
	}

	// Add custom headers
	if len(tm.config.Headers) > 0 {
		options = append(options, otlptracehttp.WithHeaders(tm.config.Headers))
	}

	return otlptrace.New(ctx, otlptracehttp.NewClient(options...))
}

// createStdoutExporter creates a stdout exporter for development
func (tm *TracerManager) createStdoutExporter() (sdktrace.SpanExporter, error) {
	return stdouttrace.New(
		stdouttrace.WithPrettyPrint(),
		stdouttrace.WithoutTimestamps(), // Remove timestamps for cleaner output
	)
}

// noopExporter is a no-op span exporter
type noopExporter struct{}

func (e *noopExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	return nil
}

func (e *noopExporter) Shutdown(ctx context.Context) error {
	return nil
}

// SpanAttributeBuilder helps build span attributes consistently
type SpanAttributeBuilder struct {
	attributes []attribute.KeyValue
}

// NewSpanAttributeBuilder creates a new span attribute builder
func NewSpanAttributeBuilder() *SpanAttributeBuilder {
	return &SpanAttributeBuilder{
		attributes: make([]attribute.KeyValue, 0),
	}
}

// String adds a string attribute
func (b *SpanAttributeBuilder) String(key, value string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.String(key, value))
	return b
}

// Int adds an integer attribute
func (b *SpanAttributeBuilder) Int(key string, value int) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.Int(key, value))
	return b
}

// Int64 adds an int64 attribute
func (b *SpanAttributeBuilder) Int64(key string, value int64) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.Int64(key, value))
	return b
}

// Float64 adds a float64 attribute
func (b *SpanAttributeBuilder) Float64(key string, value float64) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.Float64(key, value))
	return b
}

// Bool adds a boolean attribute
func (b *SpanAttributeBuilder) Bool(key string, value bool) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.Bool(key, value))
	return b
}

// UserID adds user identification attributes
func (b *SpanAttributeBuilder) UserID(userID string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.String("user.id", userID))
	return b
}

// UserName adds username attribute
func (b *SpanAttributeBuilder) UserName(username string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.String("user.name", username))
	return b
}

// Component adds component name attribute
func (b *SpanAttributeBuilder) Component(component string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.String("component", component))
	return b
}

// Operation adds operation name attribute
func (b *SpanAttributeBuilder) Operation(operation string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.String("operation", operation))
	return b
}

// Resource adds resource attributes
func (b *SpanAttributeBuilder) Resource(resourceType, resourceID string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes,
		attribute.String("resource.type", resourceType),
		attribute.String("resource.id", resourceID),
	)
	return b
}

// Error adds error attributes
func (b *SpanAttributeBuilder) Error(err error) *SpanAttributeBuilder {
	if err != nil {
		b.attributes = append(b.attributes,
			attribute.Bool("error", true),
			attribute.String("error.message", err.Error()),
		)
	}
	return b
}

// Security adds security-related attributes
func (b *SpanAttributeBuilder) Security(threatLevel, validatorType string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes,
		attribute.String("security.threat_level", threatLevel),
		attribute.String("security.validator", validatorType),
	)
	return b
}

// Cache adds cache-related attributes
func (b *SpanAttributeBuilder) Cache(hit bool, key string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes,
		attribute.Bool("cache.hit", hit),
		attribute.String("cache.key", key),
	)
	return b
}

// MCP adds MCP-specific attributes
func (b *SpanAttributeBuilder) MCP(method, toolName string) *SpanAttributeBuilder {
	if method != "" {
		b.attributes = append(b.attributes, attribute.String("mcp.method", method))
	}
	if toolName != "" {
		b.attributes = append(b.attributes, attribute.String("mcp.tool", toolName))
	}
	return b
}

// Transport adds transport-related attributes
func (b *SpanAttributeBuilder) Transport(transportType string) *SpanAttributeBuilder {
	b.attributes = append(b.attributes, attribute.String("transport.type", transportType))
	return b
}

// Build returns the built attributes
func (b *SpanAttributeBuilder) Build() []attribute.KeyValue {
	return b.attributes
}

// Helper functions for common tracing patterns

// StartSpan starts a new span with common attributes
func StartSpan(ctx context.Context, tracer trace.Tracer, operationName string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer.Start(ctx, operationName, trace.WithAttributes(attrs...))
}

// RecordError records an error in the span and sets status
func RecordError(span trace.Span, err error) {
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
}

// RecordSuccess sets the span status to OK
func RecordSuccess(span trace.Span) {
	span.SetStatus(codes.Ok, "")
}

// AddEvent adds an event to the span with attributes
func AddEvent(span trace.Span, name string, attrs ...attribute.KeyValue) {
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// SetSpanAttributes adds multiple attributes to a span
func SetSpanAttributes(span trace.Span, attrs ...attribute.KeyValue) {
	span.SetAttributes(attrs...)
}
