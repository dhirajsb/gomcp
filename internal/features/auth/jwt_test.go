package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dhirajsb/gomcp/pkg/features"
)

func TestNewJWT(t *testing.T) {
	authenticator := NewJWT("test-auth", "secret123")

	if authenticator.Name() != "test-auth" {
		t.Errorf("Expected name 'test-auth', got '%s'", authenticator.Name())
	}

	if authenticator.config.Secret != "secret123" {
		t.Errorf("Expected secret 'secret123', got '%s'", authenticator.config.Secret)
	}
}

func TestJWTAuthenticator_Name(t *testing.T) {
	authenticator := NewJWT("my-jwt-auth", "secret")

	if authenticator.Name() != "my-jwt-auth" {
		t.Errorf("Expected name 'my-jwt-auth', got '%s'", authenticator.Name())
	}
}

func TestJWTAuthenticator_Authenticate_EmptyToken(t *testing.T) {
	authenticator := NewJWT("test", "secret123")
	ctx := context.Background()

	_, err := authenticator.Authenticate(ctx, "")
	if err == nil {
		t.Error("Expected error for empty token, got nil")
	}
}

func TestJWTAuthenticator_Authenticate_ValidToken(t *testing.T) {
	secret := "secret123"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create a real JWT token for testing
	token := createTestJWT(secret, map[string]interface{}{
		"sub":      "user123",
		"username": "testuser",
		"email":    "test@example.com",
		"roles":    []string{"user"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
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

	if len(user.Roles) != 1 || user.Roles[0] != "user" {
		t.Errorf("Expected roles ['user'], got %v", user.Roles)
	}
}

func TestJWTAuthenticator_Authenticate_ExpiredToken(t *testing.T) {
	secret := "secret123"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create an expired JWT token
	token := createTestJWT(secret, map[string]interface{}{
		"sub": "user123",
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
		"exp": time.Now().Add(-time.Hour).Unix(), // Expired
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err == nil {
		t.Error("Expected error for expired token, got nil")
	}

	t.Logf("Got expected error for expired token: %v", err)
}

func TestJWTAuthenticator_Authenticate_InvalidSignature(t *testing.T) {
	secret := "secret123"
	wrongSecret := "wrong-secret"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create token with wrong secret
	token := createTestJWT(wrongSecret, map[string]interface{}{
		"sub": "user123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	_, err := authenticator.Authenticate(ctx, token)
	if err == nil {
		t.Error("Expected error for invalid signature, got nil")
	}
}

func TestJWTAuthenticator_Validate_ValidUser(t *testing.T) {
	authenticator := NewJWT("test", "secret123")
	ctx := context.Background()

	validUser := &features.UserIdentity{
		ID:       "user123",
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user"},
	}

	err := authenticator.Validate(ctx, validUser)
	if err != nil {
		t.Errorf("Expected no error for valid user, got %v", err)
	}
}

func TestJWTAuthenticator_Validate_NilUser(t *testing.T) {
	authenticator := NewJWT("test", "secret123")
	ctx := context.Background()

	err := authenticator.Validate(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil user, got nil")
	}
}

func TestJWTAuthenticator_Validate_EmptyID(t *testing.T) {
	authenticator := NewJWT("test", "secret123")
	ctx := context.Background()

	invalidUser := &features.UserIdentity{
		ID:       "", // Empty ID
		Username: "testuser",
	}

	err := authenticator.Validate(ctx, invalidUser)
	if err == nil {
		t.Error("Expected error for empty user ID, got nil")
	}
}

func TestJWTAuthenticator_Validate_EmptyUsername(t *testing.T) {
	authenticator := NewJWT("test", "secret123")
	ctx := context.Background()

	invalidUser := &features.UserIdentity{
		ID:       "user123",
		Username: "", // Empty username
	}

	err := authenticator.Validate(ctx, invalidUser)
	if err == nil {
		t.Error("Expected error for empty username, got nil")
	}
}

func TestJWTAuthenticator_BearerPrefix(t *testing.T) {
	secret := "secret123"
	authenticator := NewJWT("test", secret)
	ctx := context.Background()

	// Create a valid JWT token
	token := createTestJWT(secret, map[string]interface{}{
		"sub": "user123",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	// Test with Bearer prefix
	bearerToken := "Bearer " + token
	user, err := authenticator.Authenticate(ctx, bearerToken)
	if err != nil {
		t.Fatalf("Expected no error for Bearer token, got %v", err)
	}

	if user.ID != "user123" {
		t.Errorf("Expected user ID 'user123', got '%s'", user.ID)
	}
}

// Helper function to create test JWT tokens
func createTestJWT(secret string, claims map[string]interface{}) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		panic("Failed to create test JWT token: " + err.Error())
	}
	return tokenString
}
