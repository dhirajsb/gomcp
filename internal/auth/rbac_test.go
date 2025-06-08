package auth

import (
	"testing"
	"time"
)

func TestNewInMemoryRBAC(t *testing.T) {
	rbac := NewInMemoryRBAC()

	if rbac == nil {
		t.Fatal("Expected RBAC manager to be created")
	}

	// Check that default roles are created
	roles, err := rbac.ListRoles()
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	expectedRoles := []string{"admin", "user", "readonly", "anonymous"}
	if len(roles) != len(expectedRoles) {
		t.Errorf("Expected %d default roles, got %d", len(expectedRoles), len(roles))
	}

	// Check admin role exists and has permissions
	adminRole, err := rbac.GetRole("admin")
	if err != nil {
		t.Errorf("Expected no error getting admin role, got %v", err)
	}

	if adminRole.Name != "admin" {
		t.Errorf("Expected admin role name, got %s", adminRole.Name)
	}

	if len(adminRole.Permissions) == 0 {
		t.Error("Expected admin role to have permissions")
	}
}

func TestInMemoryRBAC_CreateRole(t *testing.T) {
	rbac := NewInMemoryRBAC()

	role := &Role{
		Name:        "developer",
		Description: "Developer role",
		Permissions: []Permission{
			{
				Resource:    "tools",
				Action:      "call",
				Target:      "*",
				Description: "Can call any tool",
			},
		},
	}

	err := rbac.CreateRole(role)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Try to create the same role again - should fail
	err = rbac.CreateRole(role)
	if err == nil {
		t.Error("Expected error when creating duplicate role")
	}
}

func TestInMemoryRBAC_GetRole(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Test getting existing role
	role, err := rbac.GetRole("admin")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if role.Name != "admin" {
		t.Errorf("Expected role name admin, got %s", role.Name)
	}

	// Test getting non-existent role
	_, err = rbac.GetRole("nonexistent")
	if err == nil {
		t.Error("Expected error when getting non-existent role")
	}
}

func TestInMemoryRBAC_UpdateRole(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Create a role first
	role := &Role{
		Name:        "tester",
		Description: "Initial description",
	}
	rbac.CreateRole(role)

	// Update the role
	role.Description = "Updated description"
	err := rbac.UpdateRole(role)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify the update
	updatedRole, _ := rbac.GetRole("tester")
	if updatedRole.Description != "Updated description" {
		t.Errorf("Expected updated description, got %s", updatedRole.Description)
	}

	// Try to update non-existent role
	nonExistentRole := &Role{Name: "nonexistent"}
	err = rbac.UpdateRole(nonExistentRole)
	if err == nil {
		t.Error("Expected error when updating non-existent role")
	}
}

func TestInMemoryRBAC_DeleteRole(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Create a role first
	role := &Role{Name: "temporary"}
	rbac.CreateRole(role)

	// Delete the role
	err := rbac.DeleteRole("temporary")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Verify deletion
	_, err = rbac.GetRole("temporary")
	if err == nil {
		t.Error("Expected error when getting deleted role")
	}

	// Try to delete system role - should fail
	err = rbac.DeleteRole("admin")
	if err == nil {
		t.Error("Expected error when deleting system role")
	}
}

func TestInMemoryRBAC_CreatePolicy(t *testing.T) {
	rbac := NewInMemoryRBAC()

	policy := &Policy{
		Name:        "test-policy",
		Description: "Test policy",
		Rules: []PolicyRule{
			{
				Effect:   "deny",
				Resource: "sensitive",
				Action:   "*",
				Target:   "*",
			},
		},
		Priority: 100,
		Subjects: []string{"user1", "user2"},
	}

	err := rbac.CreatePolicy(policy)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Try to create the same policy again - should fail
	err = rbac.CreatePolicy(policy)
	if err == nil {
		t.Error("Expected error when creating duplicate policy")
	}
}

func TestInMemoryRBAC_GetPolicy(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Create a policy first
	policy := &Policy{
		Name:        "test-policy",
		Description: "Test policy",
	}
	rbac.CreatePolicy(policy)

	// Get the policy
	retrievedPolicy, err := rbac.GetPolicy("test-policy")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if retrievedPolicy.Name != "test-policy" {
		t.Errorf("Expected policy name test-policy, got %s", retrievedPolicy.Name)
	}

	// Test getting non-existent policy
	_, err = rbac.GetPolicy("nonexistent")
	if err == nil {
		t.Error("Expected error when getting non-existent policy")
	}
}

func TestInMemoryRBAC_HasPermission(t *testing.T) {
	rbac := NewInMemoryRBAC()

	user := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	// Test with default user role permissions
	// User role should have tools/list permission
	hasPermission := rbac.HasPermission(user, "tools", "list", "*")
	if !hasPermission {
		t.Error("Expected user to have tools/list permission")
	}

	// User role should have tools/call permission
	hasPermission = rbac.HasPermission(user, "tools", "call", "*")
	if !hasPermission {
		t.Error("Expected user to have tools/call permission")
	}

	// User role should NOT have system admin permissions
	hasPermission = rbac.HasPermission(user, "system", "admin", "*")
	if hasPermission {
		t.Error("Expected user to NOT have system/admin permission")
	}

	// Test with admin user
	adminUser := &UserIdentity{
		ID:       "admin1",
		Username: "admin",
		Roles:    []string{"admin"},
	}

	// Admin should have all permissions
	hasPermission = rbac.HasPermission(adminUser, "system", "admin", "*")
	if !hasPermission {
		t.Error("Expected admin to have system/admin permission")
	}

	// Test with nil user
	hasPermission = rbac.HasPermission(nil, "tools", "list", "*")
	if hasPermission {
		t.Error("Expected nil user to have no permissions")
	}
}

func TestInMemoryRBAC_HasPermission_WithPolicies(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Create a deny policy
	policy := &Policy{
		Name:        "deny-sensitive",
		Description: "Deny access to sensitive resources",
		Rules: []PolicyRule{
			{
				Effect:   "deny",
				Resource: "sensitive",
				Action:   "*",
				Target:   "*",
			},
		},
		Priority: 100,
		Subjects: []string{"user1"},
	}
	rbac.CreatePolicy(policy)

	user := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"admin"}, // Admin role, but policy should deny
	}

	// Should be denied by policy even though user has admin role
	hasPermission := rbac.HasPermission(user, "sensitive", "read", "*")
	if hasPermission {
		t.Error("Expected policy to deny access to sensitive resource")
	}

	// Should allow access to non-sensitive resources
	hasPermission = rbac.HasPermission(user, "tools", "list", "*")
	if !hasPermission {
		t.Error("Expected policy to allow access to tools")
	}
}

func TestInMemoryRBAC_AssignRoleToUser(t *testing.T) {
	rbac := NewInMemoryRBAC()

	err := rbac.AssignRoleToUser("user1", "admin")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Get user roles
	roles, err := rbac.GetUserRoles("user1")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(roles) != 1 || roles[0] != "admin" {
		t.Errorf("Expected user1 to have admin role, got %v", roles)
	}

	// Assign another role
	err = rbac.AssignRoleToUser("user1", "user")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	roles, _ = rbac.GetUserRoles("user1")
	if len(roles) != 2 {
		t.Errorf("Expected user1 to have 2 roles, got %d", len(roles))
	}

	// Try to assign non-existent role
	err = rbac.AssignRoleToUser("user1", "nonexistent")
	if err == nil {
		t.Error("Expected error when assigning non-existent role")
	}
}

func TestInMemoryRBAC_RemoveRoleFromUser(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Assign roles first
	rbac.AssignRoleToUser("user1", "admin")
	rbac.AssignRoleToUser("user1", "user")

	// Remove one role
	err := rbac.RemoveRoleFromUser("user1", "admin")
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Check remaining roles
	roles, _ := rbac.GetUserRoles("user1")
	if len(roles) != 1 || roles[0] != "user" {
		t.Errorf("Expected user1 to have only user role, got %v", roles)
	}

	// Remove non-existent role - should not error
	err = rbac.RemoveRoleFromUser("user1", "nonexistent")
	if err != nil {
		t.Errorf("Expected no error when removing non-existent role, got %v", err)
	}
}

func TestInMemoryRBAC_GetUserPermissions(t *testing.T) {
	rbac := NewInMemoryRBAC()

	user := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"user"},
	}

	permissions := rbac.GetUserPermissions(user)
	if len(permissions) == 0 {
		t.Error("Expected user to have permissions")
	}

	// Check that user role permissions are included
	hasToolsPermission := false
	for _, perm := range permissions {
		if perm.Resource == "tools" && perm.Action == "list" {
			hasToolsPermission = true
			break
		}
	}

	if !hasToolsPermission {
		t.Error("Expected user to have tools/list permission")
	}

	// Test with nil user
	permissions = rbac.GetUserPermissions(nil)
	if permissions != nil {
		t.Error("Expected nil permissions for nil user")
	}
}

func TestInMemoryRBAC_RoleInheritance(t *testing.T) {
	rbac := NewInMemoryRBAC()

	// Create base role
	baseRole := &Role{
		Name:        "base",
		Description: "Base role",
		Permissions: []Permission{
			{
				Resource: "base",
				Action:   "read",
				Target:   "*",
			},
		},
	}
	rbac.CreateRole(baseRole)

	// Create derived role that inherits from base
	derivedRole := &Role{
		Name:        "derived",
		Description: "Derived role",
		Inherits:    []string{"base"},
		Permissions: []Permission{
			{
				Resource: "derived",
				Action:   "write",
				Target:   "*",
			},
		},
	}
	rbac.CreateRole(derivedRole)

	user := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"derived"},
	}

	// Should have permissions from derived role
	hasPermission := rbac.HasPermission(user, "derived", "write", "*")
	if !hasPermission {
		t.Error("Expected user to have derived role permissions")
	}

	// Should also have permissions from inherited base role
	hasPermission = rbac.HasPermission(user, "base", "read", "*")
	if !hasPermission {
		t.Error("Expected user to have inherited base role permissions")
	}
}

func TestInMemoryRBAC_MatchesPattern(t *testing.T) {
	rbac := NewInMemoryRBAC()

	tests := []struct {
		pattern string
		value   string
		matches bool
	}{
		{"*", "anything", true},
		{"exact", "exact", true},
		{"exact", "different", false},
		{"files/*", "files/test.txt", true},
		{"files/*", "files/subdir/test.txt", true},
		{"files/*", "documents/test.txt", false},
		{"tool:*", "tool:calculator", true},
		{"tool:*", "resource:file", false},
	}

	for _, test := range tests {
		matches := rbac.matchesPattern(test.pattern, test.value)
		if matches != test.matches {
			t.Errorf("Pattern '%s' with value '%s': expected %v, got %v",
				test.pattern, test.value, test.matches, matches)
		}
	}
}

func TestPermission(t *testing.T) {
	perm := Permission{
		Resource:    "tools",
		Action:      "call",
		Target:      "calculator",
		Conditions:  map[string]string{"env": "production"},
		Description: "Allow calling calculator tool",
	}

	if perm.Resource != "tools" {
		t.Errorf("Expected resource tools, got %s", perm.Resource)
	}

	if perm.Conditions["env"] != "production" {
		t.Error("Expected condition to be set")
	}
}

func TestRole(t *testing.T) {
	now := time.Now()
	role := Role{
		Name:        "developer",
		Description: "Developer role",
		Permissions: []Permission{
			{Resource: "code", Action: "read", Target: "*"},
			{Resource: "code", Action: "write", Target: "project/*"},
		},
		Inherits:  []string{"user"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if role.Name != "developer" {
		t.Errorf("Expected name developer, got %s", role.Name)
	}

	if len(role.Permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(role.Permissions))
	}

	if len(role.Inherits) != 1 || role.Inherits[0] != "user" {
		t.Error("Expected role to inherit from user")
	}
}

func TestPolicy(t *testing.T) {
	now := time.Now()
	policy := Policy{
		Name:        "security-policy",
		Description: "Security policy",
		Rules: []PolicyRule{
			{
				Effect:      "deny",
				Resource:    "sensitive",
				Action:      "*",
				Target:      "*",
				Description: "Deny all access to sensitive resources",
			},
		},
		Priority:  100,
		Subjects:  []string{"user1", "group:contractors"},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if policy.Name != "security-policy" {
		t.Errorf("Expected name security-policy, got %s", policy.Name)
	}

	if len(policy.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(policy.Rules))
	}

	if policy.Priority != 100 {
		t.Errorf("Expected priority 100, got %d", policy.Priority)
	}

	if policy.Rules[0].Effect != "deny" {
		t.Errorf("Expected effect deny, got %s", policy.Rules[0].Effect)
	}
}

func TestInMemoryRBAC_PolicyAppliesTo(t *testing.T) {
	rbac := NewInMemoryRBAC()

	user := &UserIdentity{
		ID:       "user1",
		Username: "testuser",
		Roles:    []string{"developer"},
		Groups:   []string{"team-alpha"},
	}

	tests := []struct {
		policy  *Policy
		applies bool
		name    string
	}{
		{
			name:    "no subjects - applies to all",
			policy:  &Policy{Subjects: []string{}},
			applies: true,
		},
		{
			name:    "wildcard subject",
			policy:  &Policy{Subjects: []string{"*"}},
			applies: true,
		},
		{
			name:    "matches user ID",
			policy:  &Policy{Subjects: []string{"user1"}},
			applies: true,
		},
		{
			name:    "matches username",
			policy:  &Policy{Subjects: []string{"testuser"}},
			applies: true,
		},
		{
			name:    "matches role",
			policy:  &Policy{Subjects: []string{"developer"}},
			applies: true,
		},
		{
			name:    "matches group",
			policy:  &Policy{Subjects: []string{"team-alpha"}},
			applies: true,
		},
		{
			name:    "no match",
			policy:  &Policy{Subjects: []string{"other-user", "other-role"}},
			applies: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			applies := rbac.policyAppliesTo(test.policy, user)
			if applies != test.applies {
				t.Errorf("Expected %v, got %v", test.applies, applies)
			}
		})
	}
}
