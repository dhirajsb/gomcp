package telemetry

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// OTLPProvider implements telemetry with OTLP exporter
type OTLPProvider struct {
	name     string
	provider *trace.TracerProvider
	endpoint string
}

// NewOTLP creates a new OTLP telemetry provider
func NewOTLP(name, endpoint string) *OTLPProvider {
	exporter, err := otlptracehttp.New(context.Background(), otlptracehttp.WithEndpoint(endpoint))
	if err != nil {
		log.Printf("Failed to create OTLP exporter: %v", err)
		return &OTLPProvider{name: name, endpoint: endpoint}
	}
	
	provider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
	)
	
	return &OTLPProvider{
		name:     name,
		provider: provider,
		endpoint: endpoint,
	}
}

func (otp *OTLPProvider) Name() string {
	return otp.name
}

func (otp *OTLPProvider) CreateTracer(serviceName string) oteltrace.Tracer {
	if otp.provider == nil {
		return otel.Tracer(serviceName)
	}
	return otp.provider.Tracer(serviceName)
}

func (otp *OTLPProvider) Shutdown(ctx context.Context) error {
	if otp.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return otp.provider.Shutdown(ctx)
}