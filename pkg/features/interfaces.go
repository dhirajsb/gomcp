// Package features defines interfaces for pluggable server components
package features

import (
	"context"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// UserIdentity represents an authenticated user (simplified public version)
type UserIdentity struct {
	ID        string
	Username  string
	Email     string
	Roles     []string
	Groups    []string
	Claims    map[string]interface{}
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Request represents an MCP request (simplified public version)
type Request struct {
	Method string
	Params interface{}
}

// LogLevel represents logging levels
type LogLevel int

const (
	TRACE LogLevel = iota
	DEBUG
	INFO
	WARN
	ERROR
	FATAL
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case TRACE:
		return "TRACE"
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "INFO"
	}
}

// Logger interface for logging implementations
type Logger interface {
	Name() string
	Log(level LogLevel, message string, fields map[string]interface{})
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
	Authenticate(ctx context.Context, token string) (*UserIdentity, error)
	Validate(ctx context.Context, user *UserIdentity) error
}

// SecurityValidator interface for security validation implementations
type SecurityValidator interface {
	Name() string
	ValidateRequest(ctx context.Context, req *Request) error
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
