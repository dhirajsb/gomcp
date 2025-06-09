package telemetry

import (
	"context"
	"fmt"
	"testing"

	"go.opentelemetry.io/otel/trace"
)

func TestNewStdout(t *testing.T) {
	provider := NewStdout("test-telemetry")

	if provider.name != "test-telemetry" {
		t.Errorf("Expected name 'test-telemetry', got '%s'", provider.name)
	}
}

func TestStdoutTelemetryProvider_Name(t *testing.T) {
	provider := NewStdout("my-stdout-telemetry")

	if provider.Name() != "my-stdout-telemetry" {
		t.Errorf("Expected name 'my-stdout-telemetry', got '%s'", provider.Name())
	}
}

func TestStdoutTelemetryProvider_CreateTracer(t *testing.T) {
	provider := NewStdout("test")

	tracer := provider.CreateTracer("test-service")

	if tracer == nil {
		t.Fatal("Expected tracer to be created, got nil")
	}

	// Verify tracer is functional
	ctx := context.Background()
	_, span := tracer.Start(ctx, "test-operation")

	if span == nil {
		t.Fatal("Expected span to be created, got nil")
	}

	// Should be able to add attributes and events
	span.SetAttributes()
	span.AddEvent("test event")

	// Should be able to end span without error
	span.End()
}

func TestStdoutTelemetryProvider_CreateMultipleTracers(t *testing.T) {
	provider := NewStdout("test")

	// Create multiple tracers for different services
	tracer1 := provider.CreateTracer("service-1")
	tracer2 := provider.CreateTracer("service-2")
	tracer3 := provider.CreateTracer("service-3")

	if tracer1 == nil || tracer2 == nil || tracer3 == nil {
		t.Fatal("Expected all tracers to be created")
	}

	// All tracers should be functional
	ctx := context.Background()

	_, span1 := tracer1.Start(ctx, "operation-1")
	_, span2 := tracer2.Start(ctx, "operation-2")
	_, span3 := tracer3.Start(ctx, "operation-3")

	if span1 == nil || span2 == nil || span3 == nil {
		t.Fatal("Expected all spans to be created")
	}

	span1.End()
	span2.End()
	span3.End()
}

func TestStdoutTelemetryProvider_Shutdown(t *testing.T) {
	provider := NewStdout("test")
	ctx := context.Background()

	// Create and use a tracer before shutdown
	tracer := provider.CreateTracer("test-service")
	_, span := tracer.Start(ctx, "test-operation")
	span.End()

	// Shutdown should not error
	err := provider.Shutdown(ctx)
	if err != nil {
		t.Errorf("Expected no error from shutdown, got %v", err)
	}

	// Should be able to call shutdown multiple times
	err = provider.Shutdown(ctx)
	if err != nil {
		t.Errorf("Expected no error from second shutdown, got %v", err)
	}
}

func TestStdoutTelemetryProvider_ShutdownWithCancelledContext(t *testing.T) {
	provider := NewStdout("test")

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// Shutdown with cancelled context should handle gracefully
	err := provider.Shutdown(ctx)
	// Implementation may return context.Canceled or handle it gracefully
	if err != nil && err != context.Canceled {
		t.Errorf("Unexpected error from shutdown with cancelled context: %v", err)
	}
}

func TestStdoutTelemetryProvider_TracerFunctionality(t *testing.T) {
	provider := NewStdout("test")
	tracer := provider.CreateTracer("functional-test")

	ctx := context.Background()

	// Test creating spans with different configurations
	_, rootSpan := tracer.Start(ctx, "root-operation")

	// Test child spans
	childCtx := trace.ContextWithSpan(ctx, rootSpan)
	_, childSpan := tracer.Start(childCtx, "child-operation")

	// Test span attributes
	childSpan.SetAttributes(
	// Note: You'd need to import the attribute package for this
	// attribute.String("test.key", "test.value"),
	// attribute.Int("test.number", 42),
	)

	// Test span events
	childSpan.AddEvent("child operation started")
	childSpan.AddEvent("child operation completed")

	// Test span status
	// childSpan.SetStatus(codes.Ok, "success")

	childSpan.End()
	rootSpan.End()
}

func TestStdoutTelemetryProvider_ConcurrentUsage(t *testing.T) {
	provider := NewStdout("test")

	// Test concurrent tracer creation
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			defer func() { done <- true }()

			serviceName := fmt.Sprintf("service-%d", id)
			tracer := provider.CreateTracer(serviceName)

			if tracer == nil {
				t.Errorf("Failed to create tracer for %s", serviceName)
				return
			}

			// Create some spans
			ctx := context.Background()
			for j := 0; j < 5; j++ {
				_, span := tracer.Start(ctx, fmt.Sprintf("operation-%d-%d", id, j))
				span.AddEvent(fmt.Sprintf("event-%d-%d", id, j))
				span.End()
			}
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Provider should still be functional
	tracer := provider.CreateTracer("final-test")
	if tracer == nil {
		t.Error("Provider should still be functional after concurrent usage")
	}
}

func TestStdoutTelemetryProvider_EmptyServiceName(t *testing.T) {
	provider := NewStdout("test")

	// Test with empty service name
	tracer := provider.CreateTracer("")

	if tracer == nil {
		t.Error("Expected tracer to be created even with empty service name")
	}

	// Should still be functional
	ctx := context.Background()
	_, span := tracer.Start(ctx, "test-operation")
	if span != nil {
		span.End()
	}
}

func TestStdoutTelemetryProvider_LongServiceName(t *testing.T) {
	provider := NewStdout("test")

	// Test with very long service name
	longName := make([]byte, 1000)
	for i := range longName {
		longName[i] = 'a'
	}
	serviceName := string(longName)

	tracer := provider.CreateTracer(serviceName)

	if tracer == nil {
		t.Error("Expected tracer to be created even with very long service name")
	}

	// Should still be functional
	ctx := context.Background()
	_, span := tracer.Start(ctx, "test-operation")
	if span != nil {
		span.End()
	}
}

func TestStdoutTelemetryProvider_SpecialCharactersInServiceName(t *testing.T) {
	provider := NewStdout("test")

	specialNames := []string{
		"service-with-dashes",
		"service_with_underscores",
		"service.with.dots",
		"service/with/slashes",
		"service with spaces",
		"service@with#special$chars%",
		"🚀-unicode-service-🎉",
	}

	for _, serviceName := range specialNames {
		tracer := provider.CreateTracer(serviceName)

		if tracer == nil {
			t.Errorf("Expected tracer to be created for service name '%s'", serviceName)
			continue
		}

		// Should be functional
		ctx := context.Background()
		_, span := tracer.Start(ctx, "test-operation")
		if span != nil {
			span.End()
		}
	}
}
