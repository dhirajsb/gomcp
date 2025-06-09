package main

import (
	"log"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/dhirajsb/gomcp/pkg/builder"
)

func main() {
	// Example 1: Basic JWT authentication
	basicExample()
	
	// Example 2: JWT with role-based authorization
	roleBasedExample()
	
	// Example 3: JWT with custom configuration (Keycloak-style)
	keycloakExample()
	
	// Example 4: JWT with both roles and groups
	rolesAndGroupsExample()
}

func basicExample() {
	log.Println("=== Basic JWT Authentication Example ===")
	
	// Create server with basic JWT auth
	server, err := builder.New("jwt-basic", "1.0.0").
		WithAuth(builder.JWTAuth("basic-jwt", "my-secret-key")).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()
	
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()
	
	// Create a test JWT token
	token := createExampleToken("my-secret-key", jwt.MapClaims{
		"sub":      "user123",
		"username": "john.doe",
		"email":    "john@example.com",
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	
	log.Printf("Created token: %s", token[:50]+"...")
	log.Printf("Server %s is ready with basic JWT auth", server.Name())
}

func roleBasedExample() {
	log.Println("\n=== Role-Based JWT Authentication Example ===")
	
	// Create server with role-based JWT auth
	requiredRoles := []string{"admin", "moderator"}
	server, err := builder.New("jwt-roles", "1.0.0").
		WithAuth(builder.JWTAuthWithRoles("role-jwt", "role-secret", requiredRoles)).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()
	
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()
	
	// Create a test JWT token with admin role
	tokenAdmin := createExampleToken("role-secret", jwt.MapClaims{
		"sub":      "admin123",
		"username": "admin.user",
		"email":    "admin@example.com",
		"roles":    []string{"admin", "user"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	
	// Create a test JWT token without required role
	tokenUser := createExampleToken("role-secret", jwt.MapClaims{
		"sub":      "user456",
		"username": "regular.user",
		"email":    "user@example.com",
		"roles":    []string{"user"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	
	log.Printf("Admin token (should work): %s", tokenAdmin[:50]+"...")
	log.Printf("User token (should fail): %s", tokenUser[:50]+"...")
	log.Printf("Required roles: %v", requiredRoles)
}

func keycloakExample() {
	log.Println("\n=== Keycloak-Style JWT Authentication Example ===")
	
	// Create server with Keycloak-style JWT auth
	server, err := builder.New("jwt-keycloak", "1.0.0").
		WithAuth(builder.KeycloakJWTAuth(
			"keycloak-jwt",
			"keycloak-secret",
			"https://auth.example.com/realms/myrealm",
			"my-client",
			[]string{"user", "admin"},
		)).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()
	
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()
	
	// Create a Keycloak-style JWT token
	token := createExampleToken("keycloak-secret", jwt.MapClaims{
		"sub":                "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		"iss":                "https://auth.example.com/realms/myrealm",
		"aud":                "my-client",
		"preferred_username": "john.doe",
		"email":              "john@example.com",
		"realm_roles":        []string{"user", "offline_access"},
		"resource_access": map[string]interface{}{
			"my-client": map[string]interface{}{
				"roles": []string{"admin", "view-profile"},
			},
		},
		"groups": []string{"/developers", "/employees"},
		"iat":    time.Now().Unix(),
		"exp":    time.Now().Add(time.Hour).Unix(),
		"nbf":    time.Now().Unix(),
	})
	
	log.Printf("Keycloak token: %s", token[:50]+"...")
	log.Printf("Issuer: https://auth.example.com/realms/myrealm")
	log.Printf("Audience: my-client")
}

func rolesAndGroupsExample() {
	log.Println("\n=== Roles and Groups JWT Authentication Example ===")
	
	// Create server with both roles and groups authorization
	requiredRoles := []string{"editor", "admin"}
	requiredGroups := []string{"staff", "contractors"}
	
	server, err := builder.New("jwt-roles-groups", "1.0.0").
		WithAuth(builder.JWTAuthWithRolesAndGroups(
			"roles-groups-jwt",
			"complex-secret",
			requiredRoles,
			requiredGroups,
		)).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()
	
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()
	
	// Create a token with required role
	tokenWithRole := createExampleToken("complex-secret", jwt.MapClaims{
		"sub":      "editor123",
		"username": "content.editor",
		"email":    "editor@example.com",
		"roles":    []string{"editor", "writer"},
		"groups":   []string{"content-team"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	
	// Create a token with required group
	tokenWithGroup := createExampleToken("complex-secret", jwt.MapClaims{
		"sub":      "contractor456",
		"username": "external.contractor",
		"email":    "contractor@partner.com",
		"roles":    []string{"developer"},
		"groups":   []string{"contractors", "external"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	
	log.Printf("Token with editor role (should work): %s", tokenWithRole[:50]+"...")
	log.Printf("Token with contractor group (should work): %s", tokenWithGroup[:50]+"...")
	log.Printf("Required roles: %v", requiredRoles)
	log.Printf("Required groups: %v", requiredGroups)
}

func customConfigExample() {
	log.Println("\n=== Custom Configuration Example ===")
	
	// Create custom JWT configuration
	config := &builder.JWTConfig{
		Name:             "custom-jwt",
		Secret:           "custom-secret-key",
		Issuer:           "https://auth.mycompany.com",
		Audience:         "my-api-service",
		AuthorizedRoles:  []string{"api-user", "service-account"},
		AuthorizedGroups: []string{"internal-users"},
		RequireExp:       true,
		RequireIat:       true,
		RequireNbf:       true,
	}
	
	server, err := builder.New("jwt-custom", "1.0.0").
		WithAuth(builder.JWTAuthWithConfig(config)).
		WithLogger(builder.ConsoleLogger("app", "info")).
		Build()
	
	if err != nil {
		log.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()
	
	log.Printf("Server configured with custom JWT settings")
	log.Printf("Issuer: %s", config.Issuer)
	log.Printf("Audience: %s", config.Audience)
	log.Printf("Required roles: %v", config.AuthorizedRoles)
	log.Printf("Required groups: %v", config.AuthorizedGroups)
}

// Helper function to create example JWT tokens
func createExampleToken(secret string, claims jwt.MapClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}
	return tokenString
}

// Example of how to verify a token manually
func verifyTokenExample() {
	log.Println("\n=== Manual Token Verification Example ===")
	
	secret := "verification-secret"
	
	// Create a token
	token := createExampleToken(secret, jwt.MapClaims{
		"sub":      "test-user",
		"username": "testuser",
		"roles":    []string{"user"},
		"iat":      time.Now().Unix(),
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	
	// Parse and verify the token
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, jwt.ErrSignatureInvalid
		}
		return []byte(secret), nil
	})
	
	if err != nil {
		log.Printf("Token verification failed: %v", err)
		return
	}
	
	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		log.Printf("Token is valid!")
		log.Printf("Subject: %v", claims["sub"])
		log.Printf("Username: %v", claims["username"])
		log.Printf("Roles: %v", claims["roles"])
	} else {
		log.Printf("Token is invalid")
	}
}

// Example usage patterns:
//
// 1. Basic usage:
//   auth := builder.JWTAuth("my-jwt", "secret-key")
//
// 2. With required roles:
//   auth := builder.JWTAuthWithRoles("my-jwt", "secret-key", []string{"admin", "editor"})
//
// 3. With required groups:
//   auth := builder.JWTAuthWithGroups("my-jwt", "secret-key", []string{"staff", "developers"})
//
// 4. With both roles and groups:
//   auth := builder.JWTAuthWithRolesAndGroups("my-jwt", "secret-key", 
//     []string{"admin"}, []string{"internal"})
//
// 5. Keycloak integration:
//   auth := builder.KeycloakJWTAuth("keycloak", "secret", 
//     "https://auth.example.com/realms/myrealm", "my-client", []string{"user"})
//
// 6. Full custom configuration:
//   config := &builder.JWTConfig{
//     Name: "custom",
//     Secret: "secret",
//     Issuer: "https://auth.example.com",
//     Audience: "my-api",
//     AuthorizedRoles: []string{"admin"},
//     RequireExp: true,
//   }
//   auth := builder.JWTAuthWithConfig(config)