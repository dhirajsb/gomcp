package builder

import (
	"github.com/dhirajsb/gomcp/internal/features/auth"
	"github.com/dhirajsb/gomcp/internal/features/caches"
	"github.com/dhirajsb/gomcp/internal/features/loggers"
	"github.com/dhirajsb/gomcp/internal/features/metrics"
	"github.com/dhirajsb/gomcp/internal/features/security"
	"github.com/dhirajsb/gomcp/internal/features/telemetry"
	"github.com/dhirajsb/gomcp/pkg/features"
)

// Re-export configurations for public API
type JWTConfig = auth.JWTConfig
type PrometheusConfig = metrics.PrometheusConfig

// Factory functions for common feature configurations
// These provide convenient ways to create feature implementations with sensible defaults

// Logger Factories

// ConsoleLogger creates a console logger with the specified level
func ConsoleLogger(name, level string) features.Logger {
	return loggers.NewConsole(name, level)
}

// JSONLogger creates a JSON formatter logger with the specified level
func JSONLogger(name, level string) features.Logger {
	return loggers.NewJSON(name, level)
}

// DebugLogger creates a console logger with debug level
func DebugLogger(name string) features.Logger {
	return loggers.NewConsole(name, "debug")
}

// InfoLogger creates a console logger with info level
func InfoLogger(name string) features.Logger {
	return loggers.NewConsole(name, "info")
}

// ProductionLogger creates a JSON logger with info level
func ProductionLogger(name string) features.Logger {
	return loggers.NewJSON(name, "info")
}

// Cache Factories

// MemoryCache creates an in-memory cache with the specified max size
func MemoryCache(name string, maxSize int) features.Cache {
	return caches.NewMemory(name, maxSize)
}

// SmallCache creates a small in-memory cache (1000 items)
func SmallCache(name string) features.Cache {
	return caches.NewMemory(name, 1000)
}

// MediumCache creates a medium in-memory cache (10000 items)
func MediumCache(name string) features.Cache {
	return caches.NewMemory(name, 10000)
}

// LargeCache creates a large in-memory cache (100000 items)
func LargeCache(name string) features.Cache {
	return caches.NewMemory(name, 100000)
}

// Auth Factories

// JWTAuth creates a JWT authenticator with the specified secret
func JWTAuth(name, secret string) features.Authenticator {
	return auth.NewJWT(name, secret)
}

// JWTAuthWithConfig creates a JWT authenticator with full configuration
func JWTAuthWithConfig(config *auth.JWTConfig) features.Authenticator {
	return auth.NewJWTWithConfig(config)
}

// JWTAuthWithRoles creates a JWT authenticator that requires specific roles
func JWTAuthWithRoles(name, secret string, authorizedRoles []string) features.Authenticator {
	config := &auth.JWTConfig{
		Name:            name,
		Secret:          secret,
		AuthorizedRoles: authorizedRoles,
		RequireExp:      true,
		RequireIat:      true,
	}
	return auth.NewJWTWithConfig(config)
}

// JWTAuthWithGroups creates a JWT authenticator that requires specific groups
func JWTAuthWithGroups(name, secret string, authorizedGroups []string) features.Authenticator {
	config := &auth.JWTConfig{
		Name:             name,
		Secret:           secret,
		AuthorizedGroups: authorizedGroups,
		RequireExp:       true,
		RequireIat:       true,
	}
	return auth.NewJWTWithConfig(config)
}

// JWTAuthWithRolesAndGroups creates a JWT authenticator that requires specific roles or groups
func JWTAuthWithRolesAndGroups(name, secret string, authorizedRoles, authorizedGroups []string) features.Authenticator {
	config := &auth.JWTConfig{
		Name:             name,
		Secret:           secret,
		AuthorizedRoles:  authorizedRoles,
		AuthorizedGroups: authorizedGroups,
		RequireExp:       true,
		RequireIat:       true,
	}
	return auth.NewJWTWithConfig(config)
}

// KeycloakJWTAuth creates a JWT authenticator configured for Keycloak
func KeycloakJWTAuth(name, secret, issuer, audience string, authorizedRoles []string) features.Authenticator {
	config := &auth.JWTConfig{
		Name:            name,
		Secret:          secret,
		Issuer:          issuer,
		Audience:        audience,
		AuthorizedRoles: authorizedRoles,
		RequireExp:      true,
		RequireIat:      true,
		RequireNbf:      false,
	}
	return auth.NewJWTWithConfig(config)
}

// Security Factories

// StrictValidator creates a strict security validator
func StrictValidator(name string) features.SecurityValidator {
	return security.NewStrict(name)
}

// Telemetry Factories

// StdoutTelemetry creates a telemetry provider that outputs to stdout
func StdoutTelemetry(name string) features.TelemetryProvider {
	return telemetry.NewStdout(name)
}

// OTLPTelemetry creates an OTLP telemetry provider with the specified endpoint
func OTLPTelemetry(name, endpoint string) features.TelemetryProvider {
	return telemetry.NewOTLP(name, endpoint)
}

// DevTelemetry creates telemetry suitable for development (stdout)
func DevTelemetry(name string) features.TelemetryProvider {
	return telemetry.NewStdout(name + "-dev")
}

// ProdTelemetry creates telemetry suitable for production (OTLP)
func ProdTelemetry(name string) features.TelemetryProvider {
	return telemetry.NewOTLP(name+"-prod", "http://otel-collector:4318")
}

// Metrics Factories

// SimpleMetrics creates a simple metrics provider that logs to console
func SimpleMetrics(name string) features.MetricsProvider {
	return metrics.NewSimple(name)
}

// PrometheusMetrics creates a Prometheus metrics provider with default configuration
func PrometheusMetrics(name string) features.MetricsProvider {
	return metrics.NewPrometheus(name)
}

// PrometheusMetricsWithConfig creates a Prometheus metrics provider with custom configuration
func PrometheusMetricsWithConfig(name string, config *metrics.PrometheusConfig) features.MetricsProvider {
	return metrics.NewPrometheusWithConfig(name, *config)
}

// PrometheusMetricsWithHTTP creates a Prometheus metrics provider with HTTP endpoint
func PrometheusMetricsWithHTTP(name string, port int, path string) features.MetricsProvider {
	config := metrics.PrometheusConfig{
		Namespace:         "gomcp",
		Subsystem:         "server",
		EnableHTTPHandler: true,
		HTTPPath:          path,
		HTTPPort:          port,
		DurationBuckets:   []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		SizeBuckets:       []float64{100, 1024, 10240, 102400, 1048576, 10485760},
	}
	return metrics.NewPrometheusWithConfig(name, config)
}

// ProductionMetrics creates a Prometheus metrics provider suitable for production
func ProductionMetrics(serviceName, version string) features.MetricsProvider {
	config := metrics.PrometheusConfig{
		Namespace: "gomcp",
		Subsystem: "server",
		DefaultLabels: map[string]string{
			"service": serviceName,
			"version": version,
		},
		EnableHTTPHandler: true,
		HTTPPath:          "/metrics",
		HTTPPort:          9090,
		DurationBuckets:   []float64{0.001, 0.01, 0.1, 0.5, 1.0, 2.5, 5.0, 10.0},
		SizeBuckets:       []float64{100, 1024, 10240, 102400, 1048576, 10485760},
	}
	return metrics.NewPrometheusWithConfig("prometheus", config)
}

// Preset Configuration Factories

// BasicLogging returns a basic logging setup with console and JSON loggers
func BasicLogging() []features.Logger {
	return []features.Logger{
		ConsoleLogger("console", "info"),
		JSONLogger("audit", "warn"),
	}
}

// DevelopmentLogging returns logging setup suitable for development
func DevelopmentLogging() []features.Logger {
	return []features.Logger{
		DebugLogger("dev"),
		InfoLogger("console"),
	}
}

// ProductionLogging returns logging setup suitable for production
func ProductionLogging() []features.Logger {
	return []features.Logger{
		ProductionLogger("app"),
		JSONLogger("audit", "warn"),
		JSONLogger("error", "error"),
	}
}

// BasicCaching returns a basic caching setup with default and session caches
func BasicCaching() []features.Cache {
	return []features.Cache{
		MediumCache("default"),
		SmallCache("sessions"),
	}
}

// DevelopmentCaching returns caching setup suitable for development
func DevelopmentCaching() []features.Cache {
	return []features.Cache{
		SmallCache("dev"),
	}
}

// ProductionCaching returns caching setup suitable for production
func ProductionCaching() []features.Cache {
	return []features.Cache{
		LargeCache("default"),
		MediumCache("sessions"),
		SmallCache("temp"),
	}
}

// Configuration Builder Helpers

// WithBasicLogging adds basic logging to a builder
func (b *Builder) WithBasicLogging() *Builder {
	for _, logger := range BasicLogging() {
		b.WithLogger(logger)
	}
	return b
}

// WithDevelopmentLogging adds development logging to a builder
func (b *Builder) WithDevelopmentLogging() *Builder {
	for _, logger := range DevelopmentLogging() {
		b.WithLogger(logger)
	}
	return b
}

// WithProductionLogging adds production logging to a builder
func (b *Builder) WithProductionLogging() *Builder {
	for _, logger := range ProductionLogging() {
		b.WithLogger(logger)
	}
	return b
}

// WithBasicCaching adds basic caching to a builder
func (b *Builder) WithBasicCaching() *Builder {
	for _, cache := range BasicCaching() {
		b.WithCache(cache)
	}
	return b
}

// WithDevelopmentCaching adds development caching to a builder
func (b *Builder) WithDevelopmentCaching() *Builder {
	for _, cache := range DevelopmentCaching() {
		b.WithCache(cache)
	}
	return b
}

// WithProductionCaching adds production caching to a builder
func (b *Builder) WithProductionCaching() *Builder {
	for _, cache := range ProductionCaching() {
		b.WithCache(cache)
	}
	return b
}

// Convenience builders for complete setups

// QuickDev creates a builder with all development features configured
func QuickDev(name, version string) *Builder {
	return New(name, version).
		WithDevelopmentLogging().
		WithDevelopmentCaching().
		WithTelemetry(DevTelemetry(name)).
		WithMetrics(SimpleMetrics("dev"))
}

// QuickProd creates a builder with all production features configured
func QuickProd(name, version string) *Builder {
	return New(name, version).
		WithProductionLogging().
		WithProductionCaching().
		WithSecurity(StrictValidator("security")).
		WithTelemetry(ProdTelemetry(name)).
		WithMetrics(ProductionMetrics(name, version))
}

// Preset builder methods for common configurations

// Minimal creates a builder with minimal configuration (no optional features)
func Minimal(name, version string) *Builder {
	return New(name, version)
}

// Development creates a builder with common development features
func Development(name, version string) *Builder {
	return New(name, version).
		WithLogger(ConsoleLogger("console", "info")).
		WithCache(SmallCache("default")).
		WithTelemetry(StdoutTelemetry("dev"))
}

// Production creates a builder with common production features
func Production(name, version string) *Builder {
	return New(name, version).
		WithLogger(JSONLogger("app", "info")).
		WithLogger(JSONLogger("audit", "warn")).
		WithCache(MediumCache("default")).
		WithSecurity(StrictValidator("security")).
		WithTelemetry(OTLPTelemetry("prod", "http://otel-collector:4318")).
		WithMetrics(ProductionMetrics(name, version))
}
