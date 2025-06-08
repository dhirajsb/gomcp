package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dhirajsb/gomcp/internal/auth"
)

// JWTAuthenticator implements JWT-based authentication
type JWTAuthenticator struct {
	name   string
	secret string
}

// NewJWT creates a new JWT authenticator
func NewJWT(name, secret string) *JWTAuthenticator {
	return &JWTAuthenticator{
		name:   name,
		secret: secret,
	}
}

func (ja *JWTAuthenticator) Name() string {
	return ja.name
}

func (ja *JWTAuthenticator) Authenticate(ctx context.Context, token string) (*auth.UserIdentity, error) {
	// Simplified JWT validation (in real implementation, use proper JWT library)
	if token == "" {
		return nil, fmt.Errorf("no token provided")
	}
	
	// Mock validation
	if strings.HasPrefix(token, "valid-") {
		return &auth.UserIdentity{
			ID:       "user123",
			Username: "testuser",
			Email:    "test@example.com",
			Roles:    []string{"user"},
			IssuedAt: time.Now(),
		}, nil
	}
	
	return nil, fmt.Errorf("invalid token")
}

func (ja *JWTAuthenticator) Validate(ctx context.Context, user *auth.UserIdentity) error {
	if user.ID == "" {
		return fmt.Errorf("user ID required")
	}
	return nil
}