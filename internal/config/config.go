package config

import (
	"fmt"
	"time"

	"github.com/dhirajsb/gomcp/internal/auth"
	"github.com/dhirajsb/gomcp/internal/cache"
	"github.com/dhirajsb/gomcp/internal/logging"
	"github.com/dhirajsb/gomcp/internal/security"
	"github.com/dhirajsb/gomcp/internal/telemetry"
)

// ServerConfig holds all configuration for the MCP server
type ServerConfig struct {
	// Core server settings (always required)
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`

	// Enterprise feature configurations (all optional)
	Auth      *AuthConfig      `json:"auth,omitempty" yaml:"auth,omitempty"`
	Security  *SecurityConfig  `json:"security,omitempty" yaml:"security,omitempty"`
	Cache     *CacheConfig     `json:"cache,omitempty" yaml:"cache,omitempty"`
	Logging   *LoggingConfig   `json:"logging,omitempty" yaml:"logging,omitempty"`
	Telemetry *TelemetryConfig `json:"telemetry,omitempty" yaml:"telemetry,omitempty"`
}

// AuthConfig wraps the auth package configuration with enable flag
type AuthConfig struct {
	Enabled bool             `json:"enabled" yaml:"enabled"`
	Config  *auth.AuthConfig `json:"config,omitempty" yaml:"config,omitempty"`
}

// SecurityConfig wraps the security package configuration with enable flag
type SecurityConfig struct {
	Enabled bool                      `json:"enabled" yaml:"enabled"`
	Config  *security.ValidatorConfig `json:"config,omitempty" yaml:"config,omitempty"`
}

// CacheConfig wraps the cache package configuration with enable flag
type CacheConfig struct {
	Enabled bool               `json:"enabled" yaml:"enabled"`
	Config  *cache.CacheConfig `json:"config,omitempty" yaml:"config,omitempty"`
}

// LoggingConfig wraps the logging package configuration with enable flag
type LoggingConfig struct {
	Enabled bool                  `json:"enabled" yaml:"enabled"`
	Config  *logging.LoggerConfig `json:"config,omitempty" yaml:"config,omitempty"`
}

// TelemetryConfig wraps the telemetry package configuration with enable flag
type TelemetryConfig struct {
	Enabled bool                    `json:"enabled" yaml:"enabled"`
	Config  *telemetry.TracerConfig `json:"config,omitempty" yaml:"config,omitempty"`
}

// DefaultServerConfig returns a minimal configuration with all enterprise features disabled
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Name:    "mcp-server",
		Version: "1.0.0",
		// All enterprise features disabled by default (nil pointers)
	}
}

// MinimalServerConfig returns the absolute minimum configuration for core functionality
func MinimalServerConfig(name, version string) *ServerConfig {
	return &ServerConfig{
		Name:    name,
		Version: version,
		// No enterprise features configured
	}
}

// DevelopmentServerConfig returns a configuration suitable for development with optional features
func DevelopmentServerConfig(name, version string) *ServerConfig {
	return &ServerConfig{
		Name:    name,
		Version: version,

		// Optional: Simple logging for development
		Logging: &LoggingConfig{
			Enabled: true,
			Config: &logging.LoggerConfig{
				Name:      "dev-logger",
				Level:     logging.LogLevelDebug,
				Async:     false,
				Formatter: "text",
			},
		},

		// Optional: Basic caching for development
		Cache: &CacheConfig{
			Enabled: true,
			Config: &cache.CacheConfig{
				Name:           "dev-cache",
				Type:           "memory",
				Enabled:        true,
				DefaultTTL:     time.Minute * 10,
				MaxSize:        1000,
				MaxMemory:      10 * 1024 * 1024, // 10MB
				EvictionPolicy: "lru",
			},
		},

		// Optional: Development telemetry
		Telemetry: &TelemetryConfig{
			Enabled: true,
			Config: &telemetry.TracerConfig{
				ServiceName:    name + "-dev",
				ServiceVersion: version,
				Environment:    "development",
				Enabled:        true,
				SamplingRatio:  1.0,
				ExporterType:   "stdout",
			},
		},
	}
}

// ProductionServerConfig returns a configuration suitable for production with security features
func ProductionServerConfig(name, version string) *ServerConfig {
	return &ServerConfig{
		Name:    name,
		Version: version,

		// Production logging
		Logging: &LoggingConfig{
			Enabled: true,
			Config: &logging.LoggerConfig{
				Name:      "prod-logger",
				Level:     logging.LogLevelInfo,
				Async:     true,
				Formatter: "json",
			},
		},

		// Production caching
		Cache: &CacheConfig{
			Enabled: true,
			Config: &cache.CacheConfig{
				Name:           "prod-cache",
				Type:           "memory", // Could be "redis" in real production
				Enabled:        true,
				DefaultTTL:     time.Hour,
				MaxSize:        10000,
				MaxMemory:      100 * 1024 * 1024, // 100MB
				EvictionPolicy: "lru",
			},
		},

		// Production security
		Security: &SecurityConfig{
			Enabled: true,
			Config: &security.ValidatorConfig{
				Enabled:       true,
				StrictMode:    true,
				AutoSanitize:  false, // Don't auto-sanitize in production
				MaxViolations: 5,
			},
		},

		// Production authentication (disabled by default, must be explicitly configured)
		Auth: &AuthConfig{
			Enabled: false, // Must be explicitly enabled with proper provider
			Config: &auth.AuthConfig{
				Provider: "",
				Enabled:  false,
				Required: false,
			},
		},

		// Production telemetry
		Telemetry: &TelemetryConfig{
			Enabled: true,
			Config: &telemetry.TracerConfig{
				ServiceName:    name,
				ServiceVersion: version,
				Environment:    "production",
				Enabled:        true,
				SamplingRatio:  0.1, // Sample 10% in production
				ExporterType:   "otlp",
				OTLPEndpoint:   "http://otel-collector:4318",
				BatchTimeout:   5 * time.Second,
			},
		},
	}
}

// IsAuthEnabled returns true if authentication is configured and enabled
func (c *ServerConfig) IsAuthEnabled() bool {
	return c.Auth != nil && c.Auth.Enabled && c.Auth.Config != nil
}

// IsSecurityEnabled returns true if security validation is configured and enabled
func (c *ServerConfig) IsSecurityEnabled() bool {
	return c.Security != nil && c.Security.Enabled && c.Security.Config != nil
}

// IsCacheEnabled returns true if caching is configured and enabled
func (c *ServerConfig) IsCacheEnabled() bool {
	return c.Cache != nil && c.Cache.Enabled && c.Cache.Config != nil
}

// IsLoggingEnabled returns true if structured logging is configured and enabled
func (c *ServerConfig) IsLoggingEnabled() bool {
	return c.Logging != nil && c.Logging.Enabled && c.Logging.Config != nil
}

// IsTelemetryEnabled returns true if OpenTelemetry is configured and enabled
func (c *ServerConfig) IsTelemetryEnabled() bool {
	return c.Telemetry != nil && c.Telemetry.Enabled && c.Telemetry.Config != nil
}

// Validate ensures the configuration is valid
func (c *ServerConfig) Validate() error {
	if c.Name == "" {
		return fmt.Errorf("server name is required")
	}
	if c.Version == "" {
		return fmt.Errorf("server version is required")
	}

	// Validate optional configurations only if they're enabled
	if c.IsAuthEnabled() {
		if c.Auth.Config.Provider == "" {
			return fmt.Errorf("auth provider is required when authentication is enabled")
		}
	}

	if c.IsCacheEnabled() {
		if c.Cache.Config.Type == "" {
			return fmt.Errorf("cache type is required when caching is enabled")
		}
	}

	if c.IsLoggingEnabled() {
		if c.Logging.Config.Name == "" {
			return fmt.Errorf("logger name is required when logging is enabled")
		}
	}

	return nil
}

// GetFeatureSummary returns a summary of which enterprise features are enabled
func (c *ServerConfig) GetFeatureSummary() map[string]bool {
	return map[string]bool{
		"authentication": c.IsAuthEnabled(),
		"security":       c.IsSecurityEnabled(),
		"caching":        c.IsCacheEnabled(),
		"logging":        c.IsLoggingEnabled(),
		"telemetry":      c.IsTelemetryEnabled(),
	}
}
