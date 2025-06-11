package auth

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/dhirajsb/gomcp/pkg/features"
	"github.com/golang-jwt/jwt/v5"
)

// JWTConfig holds JWT authentication configuration
type JWTConfig struct {
	Name             string
	Secret           string
	Issuer           string
	Audience         string
	AuthorizedRoles  []string
	AuthorizedGroups []string
	RequireExp       bool
	RequireIat       bool
	RequireNbf       bool
}

// JWTAuthenticator implements JWT-based authentication
type JWTAuthenticator struct {
	config *JWTConfig
}

// NewJWT creates a new JWT authenticator with basic configuration
func NewJWT(name, secret string) *JWTAuthenticator {
	return &JWTAuthenticator{
		config: &JWTConfig{
			Name:       name,
			Secret:     secret,
			RequireExp: true,
			RequireIat: true,
			RequireNbf: false,
		},
	}
}

// NewJWTWithConfig creates a new JWT authenticator with full configuration
func NewJWTWithConfig(config *JWTConfig) *JWTAuthenticator {
	if config.RequireExp == false && config.RequireIat == false {
		// Set sensible defaults
		config.RequireExp = true
		config.RequireIat = true
	}
	return &JWTAuthenticator{
		config: config,
	}
}

func (ja *JWTAuthenticator) Name() string {
	return ja.config.Name
}

func (ja *JWTAuthenticator) Authenticate(ctx context.Context, token string) (*features.UserIdentity, error) {
	if token == "" {
		return nil, fmt.Errorf("no token provided")
	}

	// Remove "Bearer " prefix if present
	if strings.HasPrefix(token, "Bearer ") {
		token = strings.TrimPrefix(token, "Bearer ")
	}

	// Parse the JWT token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(ja.config.Secret), nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Verify token is valid
	if !parsedToken.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	// Extract claims
	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate standard claims
	if err := ja.validateStandardClaims(claims); err != nil {
		return nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Extract user identity from claims
	userIdentity, err := ja.extractUserIdentity(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to extract user identity: %w", err)
	}

	// Validate authorization (roles/groups)
	if err := ja.validateAuthorization(userIdentity); err != nil {
		return nil, fmt.Errorf("authorization failed: %w", err)
	}

	return userIdentity, nil
}

func (ja *JWTAuthenticator) Validate(ctx context.Context, user *features.UserIdentity) error {
	if user == nil {
		return fmt.Errorf("user cannot be nil")
	}
	if user.ID == "" {
		return fmt.Errorf("user ID required")
	}
	if user.Username == "" {
		return fmt.Errorf("username required")
	}

	// Validate token is not expired based on IssuedAt if present
	if !user.IssuedAt.IsZero() && !user.ExpiresAt.IsZero() {
		if time.Now().After(user.ExpiresAt) {
			return fmt.Errorf("user token has expired")
		}
	}

	// Re-validate authorization to ensure user still has required roles/groups
	return ja.validateAuthorization(user)
}

// validateStandardClaims validates JWT standard claims
func (ja *JWTAuthenticator) validateStandardClaims(claims jwt.MapClaims) error {
	now := time.Now()

	// Validate expiration time (exp)
	if ja.config.RequireExp {
		if exp, ok := claims["exp"]; ok {
			if expTime, err := parseTimeFromClaim(exp); err == nil {
				if now.After(expTime) {
					return fmt.Errorf("token has expired")
				}
			} else {
				return fmt.Errorf("invalid exp claim: %w", err)
			}
		} else {
			return fmt.Errorf("exp claim is required")
		}
	}

	// Validate issued at time (iat)
	if ja.config.RequireIat {
		if iat, ok := claims["iat"]; ok {
			if iatTime, err := parseTimeFromClaim(iat); err == nil {
				if now.Before(iatTime) {
					return fmt.Errorf("token used before issued")
				}
			} else {
				return fmt.Errorf("invalid iat claim: %w", err)
			}
		} else {
			return fmt.Errorf("iat claim is required")
		}
	}

	// Validate not before time (nbf)
	if ja.config.RequireNbf {
		if nbf, ok := claims["nbf"]; ok {
			if nbfTime, err := parseTimeFromClaim(nbf); err == nil {
				if now.Before(nbfTime) {
					return fmt.Errorf("token not yet valid")
				}
			} else {
				return fmt.Errorf("invalid nbf claim: %w", err)
			}
		}
	}

	// Validate issuer (iss)
	if ja.config.Issuer != "" {
		if iss, ok := claims["iss"]; ok {
			if issStr, ok := iss.(string); !ok || issStr != ja.config.Issuer {
				return fmt.Errorf("invalid issuer: expected %s, got %v", ja.config.Issuer, iss)
			}
		} else {
			return fmt.Errorf("iss claim is required")
		}
	}

	// Validate audience (aud)
	if ja.config.Audience != "" {
		if aud, ok := claims["aud"]; ok {
			audValid := false
			switch audValue := aud.(type) {
			case string:
				audValid = audValue == ja.config.Audience
			case []interface{}:
				for _, a := range audValue {
					if aStr, ok := a.(string); ok && aStr == ja.config.Audience {
						audValid = true
						break
					}
				}
			}
			if !audValid {
				return fmt.Errorf("invalid audience: expected %s, got %v", ja.config.Audience, aud)
			}
		} else {
			return fmt.Errorf("aud claim is required")
		}
	}

	return nil
}

// extractUserIdentity extracts user identity from JWT claims
func (ja *JWTAuthenticator) extractUserIdentity(claims jwt.MapClaims) (*features.UserIdentity, error) {
	// Extract required fields
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return nil, fmt.Errorf("sub claim is required")
	}

	// Create user identity
	user := &features.UserIdentity{
		ID: sub,
	}

	// Extract optional fields
	if username, ok := claims["preferred_username"].(string); ok {
		user.Username = username
	} else if username, ok := claims["username"].(string); ok {
		user.Username = username
	} else {
		user.Username = sub // fallback to sub
	}

	if email, ok := claims["email"].(string); ok {
		user.Email = email
	}

	// Extract roles from various possible claim names
	user.Roles = ja.extractStringArrayFromClaims(claims, []string{"roles", "realm_roles", "resource_access"})

	// Extract groups
	user.Groups = ja.extractStringArrayFromClaims(claims, []string{"groups", "group_membership"})

	// Extract timestamps
	if iat, ok := claims["iat"]; ok {
		if iatTime, err := parseTimeFromClaim(iat); err == nil {
			user.IssuedAt = iatTime
		}
	}

	if exp, ok := claims["exp"]; ok {
		if expTime, err := parseTimeFromClaim(exp); err == nil {
			user.ExpiresAt = expTime
		}
	}

	// Store all claims for potential future use
	user.Claims = make(map[string]interface{})
	for k, v := range claims {
		user.Claims[k] = v
	}

	return user, nil
}

// extractStringArrayFromClaims extracts string arrays from JWT claims with multiple possible field names
func (ja *JWTAuthenticator) extractStringArrayFromClaims(claims jwt.MapClaims, fieldNames []string) []string {
	var result []string

	for _, fieldName := range fieldNames {
		if value, ok := claims[fieldName]; ok {
			switch v := value.(type) {
			case []interface{}:
				for _, item := range v {
					if str, ok := item.(string); ok {
						result = append(result, str)
					}
				}
			case []string:
				result = append(result, v...)
			case string:
				// Single string value
				result = append(result, v)
			case map[string]interface{}:
				// For resource_access type claims (Keycloak style)
				for _, resource := range v {
					if resourceMap, ok := resource.(map[string]interface{}); ok {
						if rolesInterface, ok := resourceMap["roles"]; ok {
							if roles, ok := rolesInterface.([]interface{}); ok {
								for _, role := range roles {
									if roleStr, ok := role.(string); ok {
										result = append(result, roleStr)
									}
								}
							}
						}
					}
				}
			}
			if len(result) > 0 {
				break // Use first found field
			}
		}
	}

	return result
}

// validateAuthorization checks if user has required roles or groups
func (ja *JWTAuthenticator) validateAuthorization(user *features.UserIdentity) error {
	// If no authorization requirements are configured, allow all authenticated users
	if len(ja.config.AuthorizedRoles) == 0 && len(ja.config.AuthorizedGroups) == 0 {
		return nil
	}

	// Check roles
	if len(ja.config.AuthorizedRoles) > 0 {
		for _, requiredRole := range ja.config.AuthorizedRoles {
			for _, userRole := range user.Roles {
				if userRole == requiredRole {
					return nil // User has required role
				}
			}
		}
	}

	// Check groups
	if len(ja.config.AuthorizedGroups) > 0 {
		for _, requiredGroup := range ja.config.AuthorizedGroups {
			for _, userGroup := range user.Groups {
				if userGroup == requiredGroup {
					return nil // User has required group
				}
			}
		}
	}

	return fmt.Errorf("user does not have required roles %v or groups %v", ja.config.AuthorizedRoles, ja.config.AuthorizedGroups)
}

// parseTimeFromClaim parses time from JWT claim (handles both int64 and float64)
func parseTimeFromClaim(claim interface{}) (time.Time, error) {
	switch v := claim.(type) {
	case float64:
		return time.Unix(int64(v), 0), nil
	case int64:
		return time.Unix(v, 0), nil
	case int:
		return time.Unix(int64(v), 0), nil
	default:
		return time.Time{}, fmt.Errorf("invalid time claim type: %T", claim)
	}
}
