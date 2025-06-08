package builder

import (
	"context"

	"github.com/dhirajsb/gomcp/internal/auth"
	"github.com/dhirajsb/gomcp/internal/logging"
	"github.com/dhirajsb/gomcp/internal/types"
	"github.com/dhirajsb/gomcp/pkg/features"
)

// Adapter wrappers to bridge internal implementations with public interfaces

// LoggerAdapter wraps internal loggers to match the public interface
type LoggerAdapter struct {
	internal interface {
		Name() string
		Log(level logging.LogLevel, message string, fields map[string]interface{})
		Close() error
	}
}

func (a *LoggerAdapter) Name() string {
	return a.internal.Name()
}

func (a *LoggerAdapter) Log(level interface{}, message string, fields map[string]interface{}) {
	// Convert interface{} level to internal LogLevel
	var logLevel logging.LogLevel = logging.LogLevelInfo // default

	switch v := level.(type) {
	case logging.LogLevel:
		logLevel = v
	case string:
		switch v {
		case "debug", "DEBUG":
			logLevel = logging.LogLevelDebug
		case "info", "INFO":
			logLevel = logging.LogLevelInfo
		case "warn", "WARNING", "WARN":
			logLevel = logging.LogLevelWarn
		case "error", "ERROR":
			logLevel = logging.LogLevelError
		}
	}

	a.internal.Log(logLevel, message, fields)
}

func (a *LoggerAdapter) Close() error {
	return a.internal.Close()
}

// AuthenticatorAdapter wraps internal authenticators to match the public interface
type AuthenticatorAdapter struct {
	internal interface {
		Name() string
		Authenticate(ctx context.Context, token string) (*auth.UserIdentity, error)
		Validate(ctx context.Context, user *auth.UserIdentity) error
	}
}

func (a *AuthenticatorAdapter) Name() string {
	return a.internal.Name()
}

func (a *AuthenticatorAdapter) Authenticate(ctx context.Context, token string) (*features.UserIdentity, error) {
	user, err := a.internal.Authenticate(ctx, token)
	if err != nil {
		return nil, err
	}

	// Convert internal UserIdentity to public UserIdentity
	return &features.UserIdentity{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		Groups:   user.Groups,
		Claims:   user.Claims,
	}, nil
}

func (a *AuthenticatorAdapter) Validate(ctx context.Context, user *features.UserIdentity) error {
	// Convert public UserIdentity to internal UserIdentity
	internalUser := &auth.UserIdentity{
		ID:       user.ID,
		Username: user.Username,
		Email:    user.Email,
		Roles:    user.Roles,
		Groups:   user.Groups,
		Claims:   user.Claims,
	}

	return a.internal.Validate(ctx, internalUser)
}

// SecurityValidatorAdapter wraps internal security validators to match the public interface
type SecurityValidatorAdapter struct {
	internal interface {
		Name() string
		ValidateRequest(ctx context.Context, req *types.Request) error
		SanitizeParams(params map[string]interface{}) map[string]interface{}
	}
}

func (a *SecurityValidatorAdapter) Name() string {
	return a.internal.Name()
}

func (a *SecurityValidatorAdapter) ValidateRequest(ctx context.Context, req *features.Request) error {
	// Convert public Request to internal Request
	internalReq := &types.Request{
		Method: req.Method,
		Params: req.Params,
	}

	return a.internal.ValidateRequest(ctx, internalReq)
}

func (a *SecurityValidatorAdapter) SanitizeParams(params map[string]interface{}) map[string]interface{} {
	return a.internal.SanitizeParams(params)
}

// Helper functions to create adapters
func wrapLogger(logger interface {
	Name() string
	Log(level logging.LogLevel, message string, fields map[string]interface{})
	Close() error
}) features.Logger {
	return &LoggerAdapter{internal: logger}
}

func wrapAuthenticator(auth interface {
	Name() string
	Authenticate(ctx context.Context, token string) (*auth.UserIdentity, error)
	Validate(ctx context.Context, user *auth.UserIdentity) error
}) features.Authenticator {
	return &AuthenticatorAdapter{internal: auth}
}

func wrapSecurityValidator(validator interface {
	Name() string
	ValidateRequest(ctx context.Context, req *types.Request) error
	SanitizeParams(params map[string]interface{}) map[string]interface{}
}) features.SecurityValidator {
	return &SecurityValidatorAdapter{internal: validator}
}
