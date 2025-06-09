# JWT Authentication in GoMCP

This document describes how to use JWT (JSON Web Token) authentication in the GoMCP library.

## Overview

The GoMCP library provides comprehensive JWT authentication support with:

- **Production-ready JWT validation** using `github.com/golang-jwt/jwt/v5`
- **Role-based authorization** - require specific roles for access
- **Group-based authorization** - require specific groups for access  
- **Standard JWT claims validation** (exp, iat, nbf, iss, aud)
- **Flexible configuration** for various JWT providers (Keycloak, Auth0, custom)
- **Multiple username sources** (preferred_username, username, sub fallback)

## Quick Start

### Basic JWT Authentication

```go
import "github.com/dhirajsb/gomcp/pkg/builder"

// Create server with basic JWT auth
server, err := builder.New("my-server", "1.0.0").
    WithAuth(builder.JWTAuth("jwt-auth", "your-secret-key")).
    Build()
```

### Role-Based Authorization

```go
// Require users to have "admin" or "moderator" roles
server, err := builder.New("my-server", "1.0.0").
    WithAuth(builder.JWTAuthWithRoles("jwt-auth", "secret", []string{"admin", "moderator"})).
    Build()
```

### Group-Based Authorization

```go
// Require users to be in "staff" or "contractors" groups
server, err := builder.New("my-server", "1.0.0").
    WithAuth(builder.JWTAuthWithGroups("jwt-auth", "secret", []string{"staff", "contractors"})).
    Build()
```

## Configuration Options

### Full Custom Configuration

```go
config := &builder.JWTConfig{
    Name:             "custom-jwt",
    Secret:           "your-secret-key",
    Issuer:           "https://auth.example.com",
    Audience:         "my-api",
    AuthorizedRoles:  []string{"admin", "user"},
    AuthorizedGroups: []string{"staff"},
    RequireExp:       true,  // Require expiration claim
    RequireIat:       true,  // Require issued-at claim
    RequireNbf:       false, // Optional not-before claim
}

server, err := builder.New("my-server", "1.0.0").
    WithAuth(builder.JWTAuthWithConfig(config)).
    Build()
```

### Keycloak Integration

```go
// Pre-configured for Keycloak
server, err := builder.New("my-server", "1.0.0").
    WithAuth(builder.KeycloakJWTAuth(
        "keycloak-auth",
        "your-secret",
        "https://auth.example.com/realms/myrealm",
        "my-client-id",
        []string{"user", "admin"},
    )).
    Build()
```

## JWT Token Format

### Required Claims

- `sub` (subject) - User ID (required)
- `exp` (expiration) - Token expiration time (required by default)
- `iat` (issued at) - Token issued time (required by default)

### Optional Claims

- `iss` (issuer) - Token issuer (validated if configured)
- `aud` (audience) - Token audience (validated if configured)
- `nbf` (not before) - Token valid from time (optional)
- `preferred_username` - Preferred username (Keycloak style)
- `username` - Username (fallback)
- `email` - User email address
- `roles` - Array of user roles
- `groups` - Array of user groups

### Example Token Payload

```json
{
  "sub": "f47ac10b-58cc-4372-a567-0e02b2c3d479",
  "iss": "https://auth.example.com/realms/myrealm", 
  "aud": "my-client",
  "preferred_username": "john.doe",
  "email": "john@example.com",
  "roles": ["user", "admin"],
  "groups": ["/developers", "/employees"],
  "iat": 1672531200,
  "exp": 1672534800,
  "nbf": 1672531200
}
```

## Authorization Logic

### Role-Based Authorization

If `AuthorizedRoles` is configured, the user must have **at least one** of the specified roles:

```go
// User needs "admin" OR "moderator" role
AuthorizedRoles: []string{"admin", "moderator"}
```

### Group-Based Authorization  

If `AuthorizedGroups` is configured, the user must be in **at least one** of the specified groups:

```go
// User needs to be in "staff" OR "contractors" group
AuthorizedGroups: []string{"staff", "contractors"}
```

### Combined Authorization

If both roles and groups are configured, the user needs **either** a required role **or** a required group:

```go
config := &builder.JWTConfig{
    AuthorizedRoles:  []string{"admin"},     // OR
    AuthorizedGroups: []string{"staff"},     // OR
}
```

### No Authorization Requirements

If neither roles nor groups are configured, all authenticated users with valid tokens are authorized.

## Username Extraction

The library extracts usernames from JWT claims in this priority order:

1. `preferred_username` (Keycloak/OIDC standard)
2. `username` (common alternative)  
3. `sub` (subject as fallback)

## Token Sources

JWT tokens can be provided in these formats:

```
// Raw token
"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

// Bearer token (prefix automatically stripped)
"Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
```

## Provider Integration Examples

### Auth0 Integration

```go
config := &builder.JWTConfig{
    Name:     "auth0",
    Secret:   "your-auth0-secret",
    Issuer:   "https://your-domain.auth0.com/",
    Audience: "your-api-identifier",
    AuthorizedRoles: []string{"admin", "user"},
    RequireExp: true,
    RequireIat: true,
}
```

### Firebase Auth Integration

```go
config := &builder.JWTConfig{
    Name:     "firebase",
    Secret:   "your-firebase-secret",
    Issuer:   "https://securetoken.google.com/your-project-id",
    Audience: "your-project-id",
    RequireExp: true,
    RequireIat: true,
}
```

### AWS Cognito Integration

```go
config := &builder.JWTConfig{
    Name:     "cognito",
    Secret:   "your-cognito-secret",
    Issuer:   "https://cognito-idp.region.amazonaws.com/your-user-pool-id",
    Audience: "your-app-client-id",
    RequireExp: true,
    RequireIat: true,
}
```

## Security Best Practices

1. **Strong Secrets**: Use long, random secret keys (at least 256 bits)
2. **Short Expiration**: Set reasonable token expiration times (15-60 minutes)
3. **Validate Issuer**: Always validate the issuer claim for production
4. **Validate Audience**: Validate audience to prevent token reuse across services
5. **Require Standard Claims**: Enable `RequireExp` and `RequireIat` for security
6. **Role/Group Validation**: Use role or group-based authorization for fine-grained access

## Error Handling

Common JWT authentication errors:

```go
// Invalid signature
"failed to parse token: signature is invalid"

// Expired token  
"token validation failed: token has expired"

// Missing required claim
"failed to extract user identity: sub claim is required"

// Authorization failure
"authorization failed: user does not have required roles [admin] or groups [staff]"

// Invalid issuer
"token validation failed: invalid issuer: expected https://auth.example.com, got https://other.com"
```

## Testing

### Create Test Tokens

```go
import "github.com/golang-jwt/jwt/v5"

func createTestToken(secret string, claims map[string]interface{}) string {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
    tokenString, _ := token.SignedString([]byte(secret))
    return tokenString
}

// Usage
token := createTestToken("test-secret", map[string]interface{}{
    "sub":      "user123",
    "username": "testuser", 
    "roles":    []string{"admin"},
    "iat":      time.Now().Unix(),
    "exp":      time.Now().Add(time.Hour).Unix(),
})
```

### Test Authorization

```go
func TestJWTAuth(t *testing.T) {
    secret := "test-secret"
    auth := builder.JWTAuthWithRoles("test", secret, []string{"admin"})
    
    server, err := builder.New("test", "1.0.0").
        WithAuth(auth).
        Build()
    defer server.Close()
    
    // Test with valid admin token
    adminToken := createTestToken(secret, map[string]interface{}{
        "sub": "admin123",
        "roles": []string{"admin"},
        "iat": time.Now().Unix(),
        "exp": time.Now().Add(time.Hour).Unix(),
    })
    
    // Use adminToken for authenticated requests
}
```

## Migration from Mock Implementation

If upgrading from the previous mock implementation:

### Before (Mock)
```go
// Old mock implementation - tokens just needed "valid-" prefix
auth := builder.JWTAuth("jwt", "secret")
token := "valid-user123"  // This won't work anymore
```

### After (Production)
```go
// New production implementation - requires real JWT tokens
auth := builder.JWTAuth("jwt", "secret")
token := createRealJWTToken("secret", claims)
```

The new implementation provides real security with proper JWT validation, making your application production-ready.