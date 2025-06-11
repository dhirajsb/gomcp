package auth

import (
	"context"
	"testing"
	"time"

	"github.com/dhirajsb/gomcp/pkg/features"
	"github.com/golang-jwt/jwt/v5"
)

func TestJWTConfig_Defaults(t *testing.T) {
	authenticator := NewJWT("test", "secret123")

	if authenticator.config.Name != "test" {
		t.Errorf("Expected name 'test', got '%s'", authenticator.config.Name)
	}

	if authenticator.config.Secret != "secret123" {
		t.Errorf("Expected secret 'secret123', got '%s'", authenticator.config.Secret)
	}

	if !authenticator.config.RequireExp {
		t.Error("Expected RequireExp to be true by default")
	}

	if !authenticator.config.RequireIat {
		t.Error("Expected RequireIat to be true by default")
	}
}

func TestJWTConfig_WithConfig(t *testing.T) {
	config := &JWTConfig{
		Name:             "custom",
		Secret:           "secret456",
		Issuer:           "test-issuer",
		Audience:         "test-audience",
		AuthorizedRoles:  []string{"admin", "user"},
		AuthorizedGroups: []string{"staff", "developers"},
		RequireExp:       true,
		RequireIat:       true,
		RequireNbf:       true,
	}

	authenticator := NewJWTWithConfig(config)

	if authenticator.config.Name != "custom" {
		t.Errorf("Expected name 'custom', got '%s'", authenticator.config.Name)
	}

	if len(authenticator.config.AuthorizedRoles) != 2 {
		t.Errorf("Expected 2 authorized roles, got %d", len(authenticator.config.AuthorizedRoles))
	}

	if len(authenticator.config.AuthorizedGroups) != 2 {
		t.Errorf("Expected 2 authorized groups, got %d", len(authenticator.config.AuthorizedGroups))
	}
}

func TestJWTAuthenticator_ValidToken(t *testing.T) {
	secret := "test-secret-key"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create a valid JWT token
	token := createTestToken(t, secret, jwt.MapClaims{
		"sub":                "user123",
		"preferred_username": "testuser",
		"email":              "test@example.com",
		"roles":              []string{"user", "viewer"},
		"groups":             []string{"employees"},
		"iat":                time.Now().Unix(),
		"exp":                time.Now().Add(time.Hour).Unix(),
	})

	user, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error for valid token, got %v", err)
	}

	if user == nil {
		t.Fatal("Expected user to be returned, got nil")
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", user.ID)
	}

	if user.Username != "testuser" {
		t.Errorf("Expected username 'testuser', got '%s'", user.Username)
	}

	if user.Email != "test@example.com" {
		t.Errorf("Expected email 'test@example.com', got '%s'", user.Email)
	}

	if len(user.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(user.Roles))
	}

	if len(user.Groups) != 1 {
		t.Errorf("Expected 1 group, got %d", len(user.Groups))
	}
}

func TestJWTAuthenticator_ExpiredToken(t *testing.T) {
	secret := "test-secret-key"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create an expired JWT token
	token := createTestToken(t, secret, jwt.MapClaims{
		"sub": "user123",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired 1 hour ago
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}

	if !containsString(err.Error(), "expired") {
		t.Errorf("Expected error message to contain 'expired', got '%s'", err.Error())
	}
}

func TestJWTAuthenticator_InvalidSignature(t *testing.T) {
	secret := "test-secret-key"
	wrongSecret := "wrong-secret-key"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create a token with wrong secret
	token := createTestToken(t, wrongSecret, jwt.MapClaims{
		"sub": "user123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}
}

func TestJWTAuthenticator_MissingSubject(t *testing.T) {
	secret := "test-secret-key"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create a token without sub claim
	token := createTestToken(t, secret, jwt.MapClaims{
		"username": "testuser",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err == nil {
		t.Error("Expected error for missing sub claim, got nil")
	}

	if !containsString(err.Error(), "sub claim is required") {
		t.Errorf("Expected error about missing sub claim, got '%s'", err.Error())
	}
}

// Bearer prefix testing is covered in jwt_test.go

func TestJWTAuthenticator_AuthorizedRoles(t *testing.T) {
	secret := "test-secret-key"
	config := &JWTConfig{
		Name:            "test",
		Secret:          secret,
		AuthorizedRoles: []string{"admin", "editor"},
		RequireExp:      true,
		RequireIat:      true,
	}
	authenticator := NewJWTWithConfig(config)
	ctx := context.Background()

	// Test with authorized role
	token := createTestToken(t, secret, jwt.MapClaims{
		"sub":   "user123",
		"roles": []string{"admin", "viewer"},
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	user, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error for authorized role, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", user.ID)
	}

	// Test with unauthorized role
	tokenUnauth := createTestToken(t, secret, jwt.MapClaims{
		"sub":   "user456",
		"roles": []string{"viewer", "guest"},
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	_, err = authenticator.Authenticate(ctx, tokenUnauth)
	if err == nil {
		t.Error("Expected error for unauthorized role, got nil")
	}

	if !containsString(err.Error(), "does not have required roles") {
		t.Errorf("Expected authorization error, got '%s'", err.Error())
	}
}

func TestJWTAuthenticator_AuthorizedGroups(t *testing.T) {
	secret := "test-secret-key"
	config := &JWTConfig{
		Name:             "test",
		Secret:           secret,
		AuthorizedGroups: []string{"developers", "admins"},
		RequireExp:       true,
		RequireIat:       true,
	}
	authenticator := NewJWTWithConfig(config)
	ctx := context.Background()

	// Test with authorized group
	token := createTestToken(t, secret, jwt.MapClaims{
		"sub":    "user123",
		"groups": []string{"developers", "employees"},
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
	})

	user, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error for authorized group, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", user.ID)
	}
}

func TestJWTAuthenticator_IssuerValidation(t *testing.T) {
	secret := "test-secret-key"
	config := &JWTConfig{
		Name:       "test",
		Secret:     secret,
		Issuer:     "https://auth.example.com",
		RequireExp: true,
		RequireIat: true,
	}
	authenticator := NewJWTWithConfig(config)
	ctx := context.Background()

	// Test with correct issuer
	token := createTestToken(t, secret, jwt.MapClaims{
		"sub": "user123",
		"iss": "https://auth.example.com",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error for correct issuer, got %v", err)
	}

	// Test with wrong issuer
	tokenWrongIss := createTestToken(t, secret, jwt.MapClaims{
		"sub": "user123",
		"iss": "https://wrong.example.com",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = authenticator.Authenticate(ctx, tokenWrongIss)
	if err == nil {
		t.Error("Expected error for wrong issuer, got nil")
	}
}

func TestJWTAuthenticator_AudienceValidation(t *testing.T) {
	secret := "test-secret-key"
	config := &JWTConfig{
		Name:       "test",
		Secret:     secret,
		Audience:   "my-api",
		RequireExp: true,
		RequireIat: true,
	}
	authenticator := NewJWTWithConfig(config)
	ctx := context.Background()

	// Test with correct audience (string)
	token := createTestToken(t, secret, jwt.MapClaims{
		"sub": "user123",
		"aud": "my-api",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("Expected no error for correct audience, got %v", err)
	}

	// Test with correct audience (array)
	tokenArray := createTestToken(t, secret, jwt.MapClaims{
		"sub": "user123",
		"aud": []string{"other-api", "my-api"},
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err = authenticator.Authenticate(ctx, tokenArray)
	if err != nil {
		t.Fatalf("Expected no error for correct audience in array, got %v", err)
	}
}

func TestJWTAuthenticator_UsernameExtraction(t *testing.T) {
	secret := "test-secret-key"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	testCases := []struct {
		name     string
		claims   jwt.MapClaims
		expected string
	}{
		{
			name: "preferred_username",
			claims: jwt.MapClaims{
				"sub":                "user123",
				"preferred_username": "john.doe",
				"username":           "johndoe",
				"iat":                time.Now().Unix(),
				"exp":                time.Now().Add(time.Hour).Unix(),
			},
			expected: "john.doe",
		},
		{
			name: "username fallback",
			claims: jwt.MapClaims{
				"sub":      "user123",
				"username": "johndoe",
				"iat":      time.Now().Unix(),
				"exp":      time.Now().Add(time.Hour).Unix(),
			},
			expected: "johndoe",
		},
		{
			name: "sub fallback",
			claims: jwt.MapClaims{
				"sub": "user123",
				"iat": time.Now().Unix(),
				"exp": time.Now().Add(time.Hour).Unix(),
			},
			expected: "user123",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := createTestToken(t, secret, tc.claims)
			user, err := authenticator.Authenticate(ctx, token)
			if err != nil {
				t.Fatalf("Expected no error, got %v", err)
			}

			if user.Username != tc.expected {
				t.Errorf("Expected username '%s', got '%s'", tc.expected, user.Username)
			}
		})
	}
}

func TestJWTAuthenticator_Validate_Production(t *testing.T) {
	secret := "test-secret-key"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Test valid user
	validUser := &features.UserIdentity{
		ID:        "user123",
		Username:  "testuser",
		Email:     "test@example.com",
		Roles:     []string{"user"},
		IssuedAt:  time.Now().Add(-time.Hour),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	err := authenticator.Validate(ctx, validUser)
	if err != nil {
		t.Errorf("Expected no error for valid user, got %v", err)
	}

	// Test expired user
	expiredUser := &features.UserIdentity{
		ID:        "user123",
		Username:  "testuser",
		IssuedAt:  time.Now().Add(-2 * time.Hour),
		ExpiresAt: time.Now().Add(-time.Hour), // Expired
	}

	err = authenticator.Validate(ctx, expiredUser)
	if err == nil {
		t.Error("Expected error for expired user, got nil")
	}
}

// Helper functions

func createTestToken(t *testing.T, secret string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}
	return tokenString
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		len(s) > len(substr) && s[:len(substr)] == substr ||
		len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
