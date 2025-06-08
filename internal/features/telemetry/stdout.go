package telemetry

import (
	"context"
	"log"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
)

// StdoutProvider implements telemetry with stdout exporter
type StdoutProvider struct {
	name     string
	provider *trace.TracerProvider
}

// NewStdout creates a new stdout telemetry provider
func NewStdout(name string) *StdoutProvider {
	exporter, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
	if err != nil {
		log.Printf("Failed to create stdout exporter: %v", err)
		return &StdoutProvider{name: name}
	}

	provider := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
	)

	return &StdoutProvider{
		name:     name,
		provider: provider,
	}
}

func (stp *StdoutProvider) Name() string {
	return stp.name
}

func (stp *StdoutProvider) CreateTracer(serviceName string) oteltrace.Tracer {
	if stp.provider == nil {
		return otel.Tracer(serviceName)
	}
	return stp.provider.Tracer(serviceName)
}

func (stp *StdoutProvider) Shutdown(ctx context.Context) error {
	if stp.provider == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return stp.provider.Shutdown(ctx)
}
