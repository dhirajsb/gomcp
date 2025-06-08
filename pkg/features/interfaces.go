// Package features defines interfaces for pluggable server components
package features

import (
	"context"
	"time"

	"github.com/dhirajsb/gomcp/internal/auth"
	"github.com/dhirajsb/gomcp/internal/logging"
	"github.com/dhirajsb/gomcp/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// Logger interface for logging implementations
type Logger interface {
	Name() string
	Log(level logging.LogLevel, message string, fields map[string]interface{})
	Close() error
}

// Cache interface for caching implementations
type Cache interface {
	Name() string
	Get(key string) (interface{}, error)
	Set(key string, value interface{}, ttl time.Duration) error
	Delete(key string) error
	Clear() error
	Close() error
}

// Authenticator interface for authentication implementations
type Authenticator interface {
	Name() string
	Authenticate(ctx context.Context, token string) (*auth.UserIdentity, error)
	Validate(ctx context.Context, user *auth.UserIdentity) error
}

// SecurityValidator interface for security validation implementations
type SecurityValidator interface {
	Name() string
	ValidateRequest(ctx context.Context, req *types.Request) error
	SanitizeParams(params map[string]interface{}) map[string]interface{}
}

// TelemetryProvider interface for telemetry implementations
type TelemetryProvider interface {
	Name() string
	CreateTracer(serviceName string) trace.Tracer
	Shutdown(ctx context.Context) error
}

// MetricsProvider interface for metrics implementations
type MetricsProvider interface {
	Name() string
	RecordCounter(name string, value int64, labels map[string]string)
	RecordGauge(name string, value float64, labels map[string]string)
	RecordHistogram(name string, value float64, labels map[string]string)
	Close() error
}