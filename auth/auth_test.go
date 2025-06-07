package auth

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/dhirajsb/gomcp/types"
)

// Mock auth provider for testing
type MockAuthProvider struct {
	users map[string]*UserIdentity
	fail  bool
}

func NewMockAuthProvider() *MockAuthProvider {
	return &MockAuthProvider{
		users: make(map[string]*UserIdentity),
	}
}

func (m *MockAuthProvider) AddUser(token string, user *UserIdentity) {
	m.users[token] = user
}

func (m *MockAuthProvider) SetFailure(fail bool) {
	m.fail = fail
}

func (m *MockAuthProvider) Authenticate(ctx context.Context, credentials interface{}) (*UserIdentity, error) {
	if m.fail {
		return nil, ErrUnauthorized
	}

	token, ok := credentials.(string)
	if !ok {
		return nil, ErrInvalidToken
	}

	user, exists := m.users[token]
	if !exists {
		return nil, ErrUnauthorized
	}

	return user, nil
}

func (m *MockAuthProvider) ValidateToken(ctx context.Context, token string) (*UserIdentity, error) {
	if m.fail {
		return nil, ErrInvalidToken
	}

	user, exists := m.users[token]
	if !exists {
		return nil, ErrInvalidToken
	}

	return user, nil
}

func (m *MockAuthProvider) ExtractToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", ErrUnauthorized
	}

	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:], nil
	}

	return "", ErrInvalidToken
}

func (m *MockAuthProvider) GetUserFromRequest(ctx context.Context, r *http.Request) (*UserIdentity, error) {
	token, err := m.ExtractToken(r)
	if err != nil {
		return nil, err
	}

	return m.ValidateToken(ctx, token)
}

func (m *MockAuthProvider) Type() string {
	return "mock"
}

// Mock RBAC manager for testing
type MockRBACManager struct {
	permissions map[string]bool
}

func NewMockRBACManager() *MockRBACManager {
	return &MockRBACManager{
		permissions: make(map[string]bool),
	}
}

func (m *MockRBACManager) SetPermission(user, resource, action, target string, allowed bool) {
	key := user + ":" + resource + ":" + action + ":" + target
	m.permissions[key] = allowed
}

func (m *MockRBACManager) HasPermission(user *UserIdentity, resource, action, target string) bool {
	if user == nil {
		return false
	}

	key := user.ID + ":" + resource + ":" + action + ":" + target
	return m.permissions[key]
}

func (m *MockRBACManager) HasPermissionWithContext(ctx context.Context, user *UserIdentity, resource, action, target string) bool {
	return m.HasPermission(user, resource, action, target)
}

// Implement other RBAC methods (not used in auth tests)
func (m *MockRBACManager) CreateRole(role *Role) error                        { return nil }
func (m *MockRBACManager) GetRole(name string) (*Role, error)                 { return nil, nil }
func (m *MockRBACManager) UpdateRole(role *Role) error                        { return nil }
func (m *MockRBACManager) DeleteRole(name string) error                       { return nil }
func (m *MockRBACManager) ListRoles() ([]*Role, error)                        { return nil, nil }
func (m *MockRBACManager) CreatePolicy(policy *Policy) error                  { return nil }
func (m *MockRBACManager) GetPolicy(name string) (*Policy, error)             { return nil, nil }
func (m *MockRBACManager) UpdatePolicy(policy *Policy) error                  { return nil }
func (m *MockRBACManager) DeletePolicy(name string) error                     { return nil }
func (m *MockRBACManager) ListPolicies() ([]*Policy, error)                   { return nil, nil }
func (m *MockRBACManager) GetUserPermissions(user *UserIdentity) []Permission { return nil }
func (m *MockRBACManager) AssignRoleToUser(userID, roleName string) error     { return nil }
func (m *MockRBACManager) RemoveRoleFromUser(userID, roleName string) error   { return nil }
func (m *MockRBACManager) GetUserRoles(userID string) ([]string, error)       { return nil, nil }

func TestNewAuthManager(t *testing.T) {
	config := AuthConfig{
		Provider: "mock",
		Enabled:  true,
		Required: true,
	}

	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	if manager == nil {
		t.Fatal("Expected auth manager to be created")
	}

	if len(manager.providers) != 0 {
		t.Errorf("Expected 0 providers, got %d", len(manager.providers))
	}
}

func TestAuthManager_RegisterProvider(t *testing.T) {
	config := AuthConfig{Provider: "mock"}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	provider := NewMockAuthProvider()
	manager.RegisterProvider(provider)

	if len(manager.providers) != 1 {
		t.Errorf("Expected 1 provider, got %d", len(manager.providers))
	}

	if manager.providers["mock"] != provider {
		t.Error("Provider not registered correctly")
	}
}

func TestAuthManager_GetProvider(t *testing.T) {
	config := AuthConfig{Provider: "mock"}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	// Test when no provider is registered
	provider := manager.GetProvider()
	if provider != nil {
		t.Error("Expected nil provider when none registered")
	}

	// Register provider and test
	mockProvider := NewMockAuthProvider()
	manager.RegisterProvider(mockProvider)

	provider = manager.GetProvider()
	if provider != mockProvider {
		t.Error("Expected registered provider")
	}
}

func TestAuthManager_AuthenticateRequest_Disabled(t *testing.T) {
	config := AuthConfig{Enabled: false}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	req, _ := http.NewRequest("GET", "/", nil)
	ctx := context.Background()

	user, err := manager.AuthenticateRequest(ctx, req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if user.Username != "anonymous" {
		t.Errorf("Expected anonymous user, got %s", user.Username)
	}
}

func TestAuthManager_AuthenticateRequest_NoProvider(t *testing.T) {
	config := AuthConfig{
		Provider: "nonexistent",
		Enabled:  true,
		Required: true,
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	req, _ := http.NewRequest("GET", "/", nil)
	ctx := context.Background()

	user, err := manager.AuthenticateRequest(ctx, req)
	if err != ErrUnauthorized {
		t.Errorf("Expected ErrUnauthorized, got %v", err)
	}

	if user != nil {
		t.Error("Expected nil user")
	}
}

func TestAuthManager_AuthenticateRequest_Success(t *testing.T) {
	config := AuthConfig{
		Provider: "mock",
		Enabled:  true,
		Required: true,
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	// Register mock provider
	provider := NewMockAuthProvider()
	expectedUser := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"user"},
	}
	provider.AddUser("valid-token", expectedUser)
	manager.RegisterProvider(provider)

	// Create request with valid token
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	ctx := context.Background()

	user, err := manager.AuthenticateRequest(ctx, req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if user.ID != expectedUser.ID {
		t.Errorf("Expected user ID %s, got %s", expectedUser.ID, user.ID)
	}
}

func TestAuthManager_AuthenticateRequest_InvalidToken(t *testing.T) {
	config := AuthConfig{
		Provider: "mock",
		Enabled:  true,
		Required: true,
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	// Register mock provider
	provider := NewMockAuthProvider()
	manager.RegisterProvider(provider)

	// Create request with invalid token
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	ctx := context.Background()

	user, err := manager.AuthenticateRequest(ctx, req)
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}

	if user != nil {
		t.Error("Expected nil user")
	}
}

func TestAuthManager_AuthenticateConnection_Stdio(t *testing.T) {
	config := AuthConfig{
		Provider: "mock",
		Enabled:  true,
		Required: true,
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	// Register mock provider
	provider := NewMockAuthProvider()
	manager.RegisterProvider(provider)

	connectionInfo := map[string]interface{}{
		"type": "stdio",
	}

	user, err := manager.AuthenticateConnection(context.Background(), connectionInfo)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if user.Username != "local" {
		t.Errorf("Expected local user, got %s", user.Username)
	}

	if len(user.Roles) == 0 || user.Roles[0] != "admin" {
		t.Error("Expected admin role for local connection")
	}
}

func TestAuthManager_AuthenticateConnection_WithToken(t *testing.T) {
	config := AuthConfig{
		Provider: "mock",
		Enabled:  true,
		Required: true,
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	// Register mock provider
	provider := NewMockAuthProvider()
	expectedUser := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"user"},
	}
	provider.AddUser("valid-token", expectedUser)
	manager.RegisterProvider(provider)

	connectionInfo := map[string]interface{}{
		"type":  "http",
		"token": "valid-token",
	}

	user, err := manager.AuthenticateConnection(context.Background(), connectionInfo)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if user.ID != expectedUser.ID {
		t.Errorf("Expected user ID %s, got %s", expectedUser.ID, user.ID)
	}
}

func TestAuthManager_AuthorizeRequest(t *testing.T) {
	config := AuthConfig{
		Provider: "mock",
		Enabled:  true,
		Required: true,
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	user := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	// Test tools/list request
	req := &types.Request{
		Method: types.MethodToolsList,
	}

	// Set permission to allow
	rbac.SetPermission("user1", "tools", "list", "*", true)

	err := manager.AuthorizeRequest(user, req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Set permission to deny
	rbac.SetPermission("user1", "tools", "list", "*", false)

	err = manager.AuthorizeRequest(user, req)
	if err != ErrInsufficientRole {
		t.Errorf("Expected ErrInsufficientRole, got %v", err)
	}
}

func TestAuthManager_ParseRequestPermission(t *testing.T) {
	config := AuthConfig{}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	tests := []struct {
		method   string
		params   interface{}
		resource string
		action   string
		target   string
	}{
		{
			method:   types.MethodToolsList,
			resource: "tools",
			action:   "list",
			target:   "*",
		},
		{
			method:   types.MethodToolsCall,
			params:   &types.ToolsCallRequest{Name: "calculator"},
			resource: "tools",
			action:   "call",
			target:   "calculator",
		},
		{
			method:   types.MethodResourcesList,
			resource: "resources",
			action:   "list",
			target:   "*",
		},
		{
			method:   types.MethodResourcesRead,
			params:   &types.ResourcesReadRequest{URI: "file:///test.txt"},
			resource: "resources",
			action:   "read",
			target:   "file:///test.txt",
		},
		{
			method:   types.MethodPromptsList,
			resource: "prompts",
			action:   "list",
			target:   "*",
		},
		{
			method:   types.MethodPromptsGet,
			params:   &types.PromptsGetRequest{Name: "test-prompt"},
			resource: "prompts",
			action:   "get",
			target:   "test-prompt",
		},
		{
			method:   "custom/method",
			resource: "system",
			action:   "call",
			target:   "custom/method",
		},
	}

	for _, test := range tests {
		req := &types.Request{
			Method: test.method,
			Params: test.params,
		}

		resource, action, target := manager.parseRequestPermission(req)

		if resource != test.resource {
			t.Errorf("Method %s: expected resource %s, got %s", test.method, test.resource, resource)
		}
		if action != test.action {
			t.Errorf("Method %s: expected action %s, got %s", test.method, test.action, action)
		}
		if target != test.target {
			t.Errorf("Method %s: expected target %s, got %s", test.method, test.target, target)
		}
	}
}

func TestUserIdentity(t *testing.T) {
	now := time.Now()
	user := &UserIdentity{
		ID:        "user123",
		Username:  "testuser",
		Email:     "test@example.com",
		Roles:     []string{"admin", "user"},
		Groups:    []string{"developers", "admins"},
		Claims:    map[string]interface{}{"custom": "value"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}

	if user.ID != "user123" {
		t.Errorf("Expected ID user123, got %s", user.ID)
	}

	if len(user.Roles) != 2 {
		t.Errorf("Expected 2 roles, got %d", len(user.Roles))
	}

	if user.Claims["custom"] != "value" {
		t.Error("Expected custom claim to be set")
	}
}

func TestAuthConfig(t *testing.T) {
	config := AuthConfig{
		Provider:    "jwt",
		Enabled:     true,
		Required:    true,
		DefaultRole: "user",
		Config: map[string]interface{}{
			"secret": "test-secret",
		},
	}

	if config.Provider != "jwt" {
		t.Errorf("Expected provider jwt, got %s", config.Provider)
	}

	if !config.Enabled {
		t.Error("Expected config to be enabled")
	}

	if config.Config["secret"] != "test-secret" {
		t.Error("Expected config secret to be set")
	}
}

func TestAuthManager_DefaultRole(t *testing.T) {
	config := AuthConfig{
		Provider:    "mock",
		Enabled:     true,
		Required:    false,
		DefaultRole: "guest",
	}
	rbac := NewMockRBACManager()
	manager := NewAuthManager(config, rbac)

	// Register mock provider
	provider := NewMockAuthProvider()
	userWithoutRoles := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{}, // No roles
	}
	provider.AddUser("valid-token", userWithoutRoles)
	manager.RegisterProvider(provider)

	// Create request with valid token
	req, _ := http.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	ctx := context.Background()

	user, err := manager.AuthenticateRequest(ctx, req)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(user.Roles) != 1 || user.Roles[0] != "guest" {
		t.Errorf("Expected default role 'guest', got %v", user.Roles)
	}
}
