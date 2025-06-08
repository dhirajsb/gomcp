package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/dhirajsb/gomcp/internal/telemetry"
	"github.com/dhirajsb/gomcp/internal/types"
	"go.opentelemetry.io/otel/trace"
)

// Common errors
var (
	ErrUnauthorized     = errors.New("unauthorized")
	ErrInvalidToken     = errors.New("invalid token")
	ErrTokenExpired     = errors.New("token expired")
	ErrInsufficientRole = errors.New("insufficient role")
)

// UserIdentity represents an authenticated user
type UserIdentity struct {
	ID        string                 `json:"id"`
	Username  string                 `json:"username"`
	Email     string                 `json:"email,omitempty"`
	Roles     []string               `json:"roles"`
	Groups    []string               `json:"groups"`
	Claims    map[string]interface{} `json:"claims"`
	IssuedAt  time.Time              `json:"issued_at"`
	ExpiresAt time.Time              `json:"expires_at,omitempty"`
}

// AuthProvider defines the interface for authentication providers
type AuthProvider interface {
	// Authenticate validates credentials and returns user identity
	Authenticate(ctx context.Context, credentials interface{}) (*UserIdentity, error)

	// ValidateToken validates a token and returns user identity
	ValidateToken(ctx context.Context, token string) (*UserIdentity, error)

	// ExtractToken extracts token from HTTP request
	ExtractToken(r *http.Request) (string, error)

	// GetUserFromRequest gets user identity from request
	GetUserFromRequest(ctx context.Context, r *http.Request) (*UserIdentity, error)

	// Type returns the provider type
	Type() string
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	Provider    string                 `json:"provider"` // jwt, oauth2, apikey
	Enabled     bool                   `json:"enabled"`
	Required    bool                   `json:"required"` // If true, reject unauthenticated requests
	Config      map[string]interface{} `json:"config"`
	DefaultRole string                 `json:"default_role"` // Default role for authenticated users
}

// AuthManager manages authentication providers and middleware
type AuthManager struct {
	providers map[string]AuthProvider
	config    AuthConfig
	rbac      RBACManager
	metrics   *AuthMetrics
	tracer    trace.Tracer
}

// NewAuthManager creates a new authentication manager
func NewAuthManager(config AuthConfig, rbac RBACManager) *AuthManager {
	return &AuthManager{
		providers: make(map[string]AuthProvider),
		config:    config,
		rbac:      rbac,
		metrics:   NewAuthMetrics(),
	}
}

// SetTracer sets the OpenTelemetry tracer for distributed tracing
func (am *AuthManager) SetTracer(tracer trace.Tracer) {
	am.tracer = tracer
}

// RegisterProvider registers an authentication provider
func (am *AuthManager) RegisterProvider(provider AuthProvider) {
	am.providers[provider.Type()] = provider
}

// GetProvider returns the configured authentication provider
func (am *AuthManager) GetProvider() AuthProvider {
	return am.providers[am.config.Provider]
}

// AuthenticateRequest authenticates an HTTP request
func (am *AuthManager) AuthenticateRequest(ctx context.Context, r *http.Request) (*UserIdentity, error) {
	// Start distributed tracing span
	var span trace.Span
	if am.tracer != nil {
		ctx, span = telemetry.StartSpan(ctx, am.tracer, "auth.authenticate_request",
			telemetry.NewSpanAttributeBuilder().
				Component("auth").
				Operation("authenticate_request").
				String("auth.provider", am.config.Provider).
				Bool("auth.enabled", am.config.Enabled).
				Bool("auth.required", am.config.Required).
				Build()...)
		defer span.End()
	}

	start := time.Now()

	if !am.config.Enabled {
		if span != nil {
			telemetry.AddEvent(span, "authentication.disabled")
			telemetry.RecordSuccess(span)
		}
		return &UserIdentity{
			ID:       "anonymous",
			Username: "anonymous",
			Roles:    []string{"anonymous"},
		}, nil
	}

	provider := am.GetProvider()
	if provider == nil {
		if span != nil {
			telemetry.AddEvent(span, "provider.not_found")
		}
		if am.config.Required {
			am.metrics.RecordAuthAttempt("none", false, time.Since(start))
			am.metrics.RecordError(ErrUnauthorized)
			if span != nil {
				telemetry.RecordError(span, ErrUnauthorized)
			}
			return nil, ErrUnauthorized
		}
		if span != nil {
			telemetry.RecordSuccess(span)
		}
		return nil, nil
	}

	if span != nil {
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			String("auth.provider_type", provider.Type()).
			Build()...)
	}

	user, err := provider.GetUserFromRequest(ctx, r)
	latency := time.Since(start)

	if err != nil {
		am.metrics.RecordAuthAttempt(provider.Type(), false, latency)
		am.metrics.RecordError(err)
		if span != nil {
			telemetry.AddEvent(span, "authentication.failed")
			telemetry.RecordError(span, err)
		}
		if am.config.Required {
			return nil, err
		}
		return nil, nil
	}

	am.metrics.RecordAuthAttempt(provider.Type(), true, latency)
	am.metrics.RecordSessionCreated()

	// Assign default role if no roles assigned
	if len(user.Roles) == 0 && am.config.DefaultRole != "" {
		user.Roles = []string{am.config.DefaultRole}
	}

	if span != nil {
		telemetry.AddEvent(span, "authentication.successful")
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			UserID(user.ID).
			UserName(user.Username).
			String("auth.roles", fmt.Sprintf("%v", user.Roles)).
			Int("auth.roles_count", len(user.Roles)).
			Build()...)
		telemetry.RecordSuccess(span)
	}

	return user, nil
}

// AuthenticateConnection authenticates a transport connection
func (am *AuthManager) AuthenticateConnection(ctx context.Context, connectionInfo map[string]interface{}) (*UserIdentity, error) {
	if !am.config.Enabled {
		return &UserIdentity{
			ID:       "anonymous",
			Username: "anonymous",
			Roles:    []string{"anonymous"},
		}, nil
	}

	provider := am.GetProvider()
	if provider == nil {
		if am.config.Required {
			return nil, ErrUnauthorized
		}
		return nil, nil
	}

	// For stdio connections, no authentication required
	if connectionType, ok := connectionInfo["type"].(string); ok && connectionType == "stdio" {
		return &UserIdentity{
			ID:       "local",
			Username: "local",
			Roles:    []string{"admin"}, // Local connections get admin role
		}, nil
	}

	// For other connections, require token in connection info
	token, ok := connectionInfo["token"].(string)
	if !ok {
		if am.config.Required {
			return nil, ErrUnauthorized
		}
		return nil, nil
	}

	user, err := provider.ValidateToken(ctx, token)
	if err != nil {
		if am.config.Required {
			return nil, err
		}
		return nil, nil
	}

	return user, nil
}

// AuthorizeRequest checks if user has permission for MCP request
func (am *AuthManager) AuthorizeRequest(user *UserIdentity, req *types.Request) error {
	start := time.Now()

	if user == nil {
		if am.config.Required {
			am.metrics.RecordPermissionCheck(false, time.Since(start))
			return ErrUnauthorized
		}
		return nil
	}

	// Extract resource, action, and target from MCP request
	resource, action, target := am.parseRequestPermission(req)

	// Check RBAC permissions
	granted := am.rbac.HasPermission(user, resource, action, target)
	latency := time.Since(start)

	am.metrics.RecordPermissionCheck(granted, latency)

	if !granted {
		return ErrInsufficientRole
	}

	return nil
}

// parseRequestPermission extracts permission components from MCP request
func (am *AuthManager) parseRequestPermission(req *types.Request) (resource, action, target string) {
	switch req.Method {
	case types.MethodToolsList:
		return "tools", "list", "*"
	case types.MethodToolsCall:
		if params, ok := req.Params.(*types.ToolsCallRequest); ok {
			return "tools", "call", params.Name
		}
		return "tools", "call", "*"
	case types.MethodResourcesList:
		return "resources", "list", "*"
	case types.MethodResourcesRead:
		if params, ok := req.Params.(*types.ResourcesReadRequest); ok {
			return "resources", "read", params.URI
		}
		return "resources", "read", "*"
	case types.MethodPromptsList:
		return "prompts", "list", "*"
	case types.MethodPromptsGet:
		if params, ok := req.Params.(*types.PromptsGetRequest); ok {
			return "prompts", "get", params.Name
		}
		return "prompts", "get", "*"
	default:
		return "system", "call", req.Method
	}
}

// GetMetrics returns authentication metrics
func (am *AuthManager) GetMetrics() map[string]interface{} {
	return am.metrics.GetStats()
}
