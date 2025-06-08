// Package builder provides a fluent interface for configuring and building MCP servers
package builder

import (
	"context"
	"fmt"

	"github.com/dhirajsb/gomcp/internal/config"
	"github.com/dhirajsb/gomcp/internal/server"
	"github.com/dhirajsb/gomcp/internal/transport"
	"github.com/dhirajsb/gomcp/pkg/features"
)

// Builder provides a fluent interface for configuring and building MCP servers
type Builder struct {
	config *config.ServerConfig

	// Collections of feature implementations
	loggers     []features.Logger
	caches      []features.Cache
	auths       []features.Authenticator
	securities  []features.SecurityValidator
	telemetries []features.TelemetryProvider
	metrics     []features.MetricsProvider
}

// New creates a new server builder with default configuration
func New(name, version string) *Builder {
	return &Builder{
		config:      config.MinimalServerConfig(name, version),
		loggers:     make([]features.Logger, 0),
		caches:      make([]features.Cache, 0),
		auths:       make([]features.Authenticator, 0),
		securities:  make([]features.SecurityValidator, 0),
		telemetries: make([]features.TelemetryProvider, 0),
		metrics:     make([]features.MetricsProvider, 0),
	}
}

// FromConfig creates a builder from an existing configuration
func FromConfig(cfg *config.ServerConfig) *Builder {
	return &Builder{
		config:      cfg,
		loggers:     make([]features.Logger, 0),
		caches:      make([]features.Cache, 0),
		auths:       make([]features.Authenticator, 0),
		securities:  make([]features.SecurityValidator, 0),
		telemetries: make([]features.TelemetryProvider, 0),
		metrics:     make([]features.MetricsProvider, 0),
	}
}

// Core configuration methods

// WithName sets the server name
func (b *Builder) WithName(name string) *Builder {
	b.config.Name = name
	return b
}

// WithVersion sets the server version
func (b *Builder) WithVersion(version string) *Builder {
	b.config.Version = version
	return b
}

// Feature registration methods - single method per feature type

// WithLogger adds a logger implementation
func (b *Builder) WithLogger(logger features.Logger) *Builder {
	b.loggers = append(b.loggers, logger)
	return b
}

// WithCache adds a cache implementation
func (b *Builder) WithCache(cache features.Cache) *Builder {
	b.caches = append(b.caches, cache)
	return b
}

// WithAuth adds an authentication implementation
func (b *Builder) WithAuth(auth features.Authenticator) *Builder {
	b.auths = append(b.auths, auth)
	return b
}

// WithSecurity adds a security validation implementation
func (b *Builder) WithSecurity(validator features.SecurityValidator) *Builder {
	b.securities = append(b.securities, validator)
	return b
}

// WithTelemetry adds a telemetry provider implementation
func (b *Builder) WithTelemetry(provider features.TelemetryProvider) *Builder {
	b.telemetries = append(b.telemetries, provider)
	return b
}

// WithMetrics adds a metrics provider implementation
func (b *Builder) WithMetrics(provider features.MetricsProvider) *Builder {
	b.metrics = append(b.metrics, provider)
	return b
}

// Build creates and configures the MCP server
func (b *Builder) Build() (*ConfiguredServer, error) {
	// Validate configuration
	if err := b.config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create base server
	srv := server.NewServer(b.config.Name, b.config.Version)

	// Create configured server wrapper
	configuredServer := &ConfiguredServer{
		Server:      srv,
		config:      b.config,
		loggers:     b.loggers,
		caches:      b.caches,
		auths:       b.auths,
		securities:  b.securities,
		telemetries: b.telemetries,
		metrics:     b.metrics,
	}

	// Initialize features
	if err := configuredServer.initializeFeatures(); err != nil {
		return nil, fmt.Errorf("failed to initialize features: %w", err)
	}

	return configuredServer, nil
}

// BuildAndStart creates the server and starts it with the provided transport
func (b *Builder) BuildAndStart(transport transport.Transport) error {
	srv, err := b.Build()
	if err != nil {
		return err
	}
	return srv.Start(transport)
}

// GetConfig returns the current configuration
func (b *Builder) GetConfig() *config.ServerConfig {
	return b.config
}

// GetFeatureSummary returns a summary of configured features
func (b *Builder) GetFeatureSummary() map[string]int {
	return map[string]int{
		"loggers":     len(b.loggers),
		"caches":      len(b.caches),
		"auths":       len(b.auths),
		"securities":  len(b.securities),
		"telemetries": len(b.telemetries),
		"metrics":     len(b.metrics),
	}
}

// ConfiguredServer wraps the base server with configured features
type ConfiguredServer struct {
	*server.Server
	config      *config.ServerConfig
	loggers     []features.Logger
	caches      []features.Cache
	auths       []features.Authenticator
	securities  []features.SecurityValidator
	telemetries []features.TelemetryProvider
	metrics     []features.MetricsProvider
}

// initializeFeatures sets up all configured features
func (cs *ConfiguredServer) initializeFeatures() error {
	// Initialize telemetry providers and set tracer if available
	if len(cs.telemetries) > 0 {
		// Use the first telemetry provider to create a tracer
		tracer := cs.telemetries[0].CreateTracer(cs.config.Name)
		cs.Server.SetTracer(tracer)
	}

	// TODO: Initialize other features as needed
	// This would involve extending the base server to accept these features

	return nil
}

// Name returns the server name
func (cs *ConfiguredServer) Name() string {
	return cs.config.Name
}

// GetLoggers returns all configured loggers
func (cs *ConfiguredServer) GetLoggers() []features.Logger {
	return cs.loggers
}

// GetCaches returns all configured caches
func (cs *ConfiguredServer) GetCaches() []features.Cache {
	return cs.caches
}

// GetAuths returns all configured authenticators
func (cs *ConfiguredServer) GetAuths() []features.Authenticator {
	return cs.auths
}

// GetSecurities returns all configured security validators
func (cs *ConfiguredServer) GetSecurities() []features.SecurityValidator {
	return cs.securities
}

// GetTelemetries returns all configured telemetry providers
func (cs *ConfiguredServer) GetTelemetries() []features.TelemetryProvider {
	return cs.telemetries
}

// GetMetrics returns all configured metrics providers
func (cs *ConfiguredServer) GetMetrics() []features.MetricsProvider {
	return cs.metrics
}

// GetLoggerByName finds a logger by name
func (cs *ConfiguredServer) GetLoggerByName(name string) features.Logger {
	for _, logger := range cs.loggers {
		if logger.Name() == name {
			return logger
		}
	}
	return nil
}

// GetCacheByName finds a cache by name
func (cs *ConfiguredServer) GetCacheByName(name string) features.Cache {
	for _, cache := range cs.caches {
		if cache.Name() == name {
			return cache
		}
	}
	return nil
}

// GetAuthByName finds an authenticator by name
func (cs *ConfiguredServer) GetAuthByName(name string) features.Authenticator {
	for _, auth := range cs.auths {
		if auth.Name() == name {
			return auth
		}
	}
	return nil
}

// Close gracefully shuts down all features
func (cs *ConfiguredServer) Close() error {
	var errors []error

	// Close loggers
	for _, logger := range cs.loggers {
		if logger != nil {
			if err := logger.Close(); err != nil {
				errors = append(errors, err)
			}
		}
	}

	// Close caches
	for _, cache := range cs.caches {
		if cache != nil {
			if err := cache.Close(); err != nil {
				errors = append(errors, err)
			}
		}
	}

	// Close metrics providers
	for _, metrics := range cs.metrics {
		if metrics != nil {
			if err := metrics.Close(); err != nil {
				errors = append(errors, err)
			}
		}
	}

	// Shutdown telemetry providers
	for _, telemetry := range cs.telemetries {
		if telemetry != nil {
			if err := telemetry.Shutdown(context.Background()); err != nil {
				errors = append(errors, err)
			}
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("errors during shutdown: %v", errors)
	}

	return nil
}
