package gomcp

import (
	"context"
	"log"

	"github.com/dhirajsb/gomcp/auth"
	"github.com/dhirajsb/gomcp/cache"
	"github.com/dhirajsb/gomcp/config"
	"github.com/dhirajsb/gomcp/logging"
	"github.com/dhirajsb/gomcp/security"
	"github.com/dhirajsb/gomcp/server"
	"github.com/dhirajsb/gomcp/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// EnterpriseServer wraps the core MCP server with optional enterprise features
type EnterpriseServer struct {
	*server.Server
	config *config.ServerConfig

	// Optional enterprise components (nil if disabled)
	authManager     *auth.AuthManager
	securityManager *security.SecurityValidatorManager
	cacheManager    cache.Cache
	logger          logging.Logger
	tracerManager   *telemetry.TracerManager
}

// NewEnterpriseServer creates a new server with optional enterprise features
func NewEnterpriseServer(cfg *config.ServerConfig) (*EnterpriseServer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Create core server (always required)
	coreServer := server.NewServer(cfg.Name, cfg.Version)

	es := &EnterpriseServer{
		Server: coreServer,
		config: cfg,
	}

	// Initialize optional enterprise features
	if err := es.initializeOptionalFeatures(); err != nil {
		return nil, err
	}

	return es, nil
}

// NewMinimalServer creates a server with only core functionality (no enterprise features)
func NewMinimalServer(name, version string) *EnterpriseServer {
	cfg := config.MinimalServerConfig(name, version)

	// This will never fail since minimal config is always valid
	es, _ := NewEnterpriseServer(cfg)
	return es
}

// initializeOptionalFeatures sets up enterprise components based on configuration
func (es *EnterpriseServer) initializeOptionalFeatures() error {
	var tracer trace.Tracer

	// 1. Initialize telemetry first (if enabled) so other components can use it
	if es.config.IsTelemetryEnabled() {
		tracerManager := telemetry.NewTracerManager(*es.config.Telemetry.Config)
		if err := tracerManager.Initialize(context.Background()); err != nil {
			log.Printf("Warning: Failed to initialize telemetry: %v", err)
		} else {
			es.tracerManager = tracerManager
			tracer = tracerManager.GetTracer()
			es.Server.SetTracer(tracer)
		}
	}

	// 2. Initialize logging (if enabled)
	if es.config.IsLoggingEnabled() {
		logger, err := logging.NewLogger(*es.config.Logging.Config)
		if err != nil {
			log.Printf("Warning: Failed to initialize logging: %v", err)
		} else {
			es.logger = logger
		}
	}

	// 3. Initialize caching (if enabled)
	if es.config.IsCacheEnabled() {
		cacheConfig := *es.config.Cache.Config

		// Create appropriate cache type
		switch cacheConfig.Type {
		case "memory":
			memCache := cache.NewMemoryCache(cacheConfig.Name, cacheConfig)
			if tracer != nil {
				memCache.SetTracer(tracer)
			}
			es.cacheManager = memCache
		case "redis":
			// Redis cache would be initialized here if available
			log.Printf("Warning: Redis cache not implemented, falling back to memory cache")
			memCache := cache.NewMemoryCache(cacheConfig.Name, cacheConfig)
			if tracer != nil {
				memCache.SetTracer(tracer)
			}
			es.cacheManager = memCache
		default:
			log.Printf("Warning: Unknown cache type %s, caching disabled", cacheConfig.Type)
		}
	}

	// 4. Initialize security validation (if enabled)
	if es.config.IsSecurityEnabled() {
		securityManager := security.NewSecurityValidatorManager(*es.config.Security.Config)
		if tracer != nil {
			securityManager.SetTracer(tracer)
		}
		es.securityManager = securityManager
	}

	// 5. Initialize authentication (if enabled)
	if es.config.IsAuthEnabled() {
		var rbac auth.RBACManager

		// Create RBAC manager
		inMemoryRBAC := auth.NewInMemoryRBAC()
		if tracer != nil {
			inMemoryRBAC.SetTracer(tracer)
		}
		rbac = inMemoryRBAC

		// Create auth manager
		authManager := auth.NewAuthManager(*es.config.Auth.Config, rbac)
		if tracer != nil {
			authManager.SetTracer(tracer)
		}
		es.authManager = authManager
	}

	return nil
}

// Shutdown gracefully shuts down all enterprise components
func (es *EnterpriseServer) Shutdown(ctx context.Context) error {
	// Shutdown telemetry last
	if es.tracerManager != nil {
		return es.tracerManager.Shutdown(ctx)
	}
	return nil
}

// Enterprise feature accessors (return nil if feature is disabled)

// Auth returns the authentication manager if enabled, nil otherwise
func (es *EnterpriseServer) Auth() *auth.AuthManager {
	return es.authManager
}

// Security returns the security validator if enabled, nil otherwise
func (es *EnterpriseServer) Security() *security.SecurityValidatorManager {
	return es.securityManager
}

// Cache returns the cache manager if enabled, nil otherwise
func (es *EnterpriseServer) Cache() cache.Cache {
	return es.cacheManager
}

// Logger returns the structured logger if enabled, nil otherwise
func (es *EnterpriseServer) Logger() logging.Logger {
	return es.logger
}

// Tracer returns the OpenTelemetry tracer if enabled, nil otherwise
func (es *EnterpriseServer) Tracer() *telemetry.TracerManager {
	return es.tracerManager
}

// GetConfig returns the server configuration
func (es *EnterpriseServer) GetConfig() *config.ServerConfig {
	return es.config
}

// IsFeatureEnabled returns whether a specific enterprise feature is enabled
func (es *EnterpriseServer) IsFeatureEnabled(feature string) bool {
	summary := es.config.GetFeatureSummary()
	enabled, exists := summary[feature]
	return exists && enabled
}

// GetEnabledFeatures returns a list of enabled enterprise features
func (es *EnterpriseServer) GetEnabledFeatures() []string {
	var enabled []string
	summary := es.config.GetFeatureSummary()

	for feature, isEnabled := range summary {
		if isEnabled {
			enabled = append(enabled, feature)
		}
	}

	return enabled
}

// Helper methods for safe enterprise feature usage

// LogInfo logs an info message using structured logging if available, falls back to standard log
func (es *EnterpriseServer) LogInfo(message string, fields ...logging.Field) {
	if es.logger != nil {
		es.logger.WithFields(fields...).Info(message)
	} else {
		log.Printf("INFO: %s", message)
	}
}

// LogError logs an error message using structured logging if available, falls back to standard log
func (es *EnterpriseServer) LogError(message string, err error, fields ...logging.Field) {
	if es.logger != nil {
		allFields := append(fields, logging.String("error", err.Error()))
		es.logger.WithFields(allFields...).Error(message)
	} else {
		log.Printf("ERROR: %s: %v", message, err)
	}
}

// ValidateInput validates input using security validation if enabled, always returns valid if disabled
func (es *EnterpriseServer) ValidateInput(ctx context.Context, input map[string]interface{}) (*security.ValidationResult, error) {
	if es.securityManager != nil {
		return es.securityManager.ValidateInput(ctx, input)
	}

	// Return a successful validation result if security is disabled
	return &security.ValidationResult{
		Valid:      true,
		Score:      100,
		Violations: make([]security.SecurityViolation, 0),
		Sanitized:  make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}, nil
}

// GetFromCache retrieves from cache if available, returns miss if caching disabled
func (es *EnterpriseServer) GetFromCache(ctx context.Context, key string) (interface{}, error) {
	if es.cacheManager != nil {
		item, err := es.cacheManager.Get(ctx, key)
		if err != nil {
			return nil, err
		}
		return item.Value, nil
	}

	// Return cache miss if caching is disabled
	return nil, cache.ErrCacheMiss
}

// SetInCache stores in cache if available, silently succeeds if caching disabled
func (es *EnterpriseServer) SetInCache(ctx context.Context, key string, value interface{}) error {
	if es.cacheManager != nil {
		return es.cacheManager.Set(ctx, key, value, es.config.Cache.Config.DefaultTTL)
	}

	// Silently succeed if caching is disabled
	return nil
}
