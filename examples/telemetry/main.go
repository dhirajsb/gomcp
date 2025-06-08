package main

import (
	"fmt"
	"log"

	"github.com/dhirajsb/gomcp/pkg/builder"
)

// Example demonstrating telemetry integration through the builder pattern
func main() {
	fmt.Println("=== Go MCP Telemetry Integration Demo ===")
	fmt.Println("Shows how to add telemetry to your MCP server")
	fmt.Println()

	demonstrateTelemetryConfigurations()
}

func demonstrateTelemetryConfigurations() {
	fmt.Println("1. DEVELOPMENT TELEMETRY")
	fmt.Println("   Stdout telemetry for local development")
	showDevelopmentTelemetry()

	fmt.Println("\n2. PRODUCTION TELEMETRY")
	fmt.Println("   OTLP telemetry for production monitoring")
	showProductionTelemetry()

	fmt.Println("\n3. CUSTOM TELEMETRY")
	fmt.Println("   Custom telemetry configuration")
	showCustomTelemetry()

	fmt.Println("\n4. TELEMETRY BENEFITS")
	fmt.Println("   What telemetry provides for your application")
	showTelemetryBenefits()
}

func showDevelopmentTelemetry() {
	server, err := builder.Development("dev-telemetry", "1.0.0").Build()
	if err != nil {
		log.Printf("   ⚠ Failed to create development server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Telemetry: Stdout exporter for local debugging\n")
	fmt.Printf("   Benefits: Easy to see traces during development\n")
	fmt.Printf("   ✓ Development telemetry configured\n")

	server.Close()
}

func showProductionTelemetry() {
	server, err := builder.Production("prod-telemetry", "1.0.0").Build()
	if err != nil {
		log.Printf("   ⚠ Failed to create production server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Telemetry: OTLP exporter to collector\n")
	fmt.Printf("   Benefits: Distributed tracing in production\n")
	fmt.Printf("   ✓ Production telemetry configured\n")

	server.Close()
}

func showCustomTelemetry() {
	server, err := builder.New("custom-telemetry", "1.0.0").
		WithTelemetry(builder.DevTelemetry("custom")).
		WithLogger(builder.InfoLogger("app")).
		Build()

	if err != nil {
		log.Printf("   ⚠ Failed to create custom server: %v", err)
		return
	}

	fmt.Printf("   Server: %s\n", server.Name())
	fmt.Printf("   Telemetry: Custom configuration\n")
	fmt.Printf("   Benefits: Tailored to your specific needs\n")
	fmt.Printf("   ✓ Custom telemetry configured\n")

	server.Close()
}

func showTelemetryBenefits() {
	fmt.Println("   📊 Telemetry provides:")
	fmt.Println("   • End-to-end request tracing")
	fmt.Println("   • Performance bottleneck identification")
	fmt.Println("   • Error propagation tracking")
	fmt.Println("   • Service dependency mapping")
	fmt.Println("   • Latency analysis across components")
	fmt.Println("   • Integration with observability platforms")
	fmt.Println()
	fmt.Println("   🔍 Supported platforms:")
	fmt.Println("   • Jaeger (open source)")
	fmt.Println("   • OpenTelemetry Collector")
	fmt.Println("   • Cloud providers (AWS X-Ray, Google Cloud Trace)")
	fmt.Println("   • Commercial platforms (Datadog, New Relic, Honeycomb)")
}

func init() {
	fmt.Println("=== Telemetry Configuration Examples ===")
	fmt.Println()
	fmt.Println("Telemetry helps you understand:")
	fmt.Println("- How requests flow through your system")
	fmt.Println("- Where performance bottlenecks occur")
	fmt.Println("- How errors propagate through components")
	fmt.Println("- Dependencies between different services")
	fmt.Println()
}
