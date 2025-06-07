package auth

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Permission represents a single permission
type Permission struct {
	Resource    string            `json:"resource"`     // "tools", "resources", "prompts", "system"
	Action      string            `json:"action"`       // "list", "call", "read", "get", "*"
	Target      string            `json:"target"`       // "*", "tool:calculator", "resource:files/*"
	Conditions  map[string]string `json:"conditions"`   // Additional conditions
	Description string            `json:"description"`
}

// Role represents a role with permissions
type Role struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
	Inherits    []string     `json:"inherits"`    // Role inheritance
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// PolicyRule represents a single policy rule
type PolicyRule struct {
	Effect      string            `json:"effect"`      // "allow" or "deny"
	Resource    string            `json:"resource"`
	Action      string            `json:"action"`
	Target      string            `json:"target"`
	Conditions  map[string]string `json:"conditions"`
	Description string            `json:"description"`
}

// Policy represents a security policy
type Policy struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Rules       []PolicyRule `json:"rules"`
	Priority    int          `json:"priority"`    // Higher priority = evaluated first
	Subjects    []string     `json:"subjects"`    // Users, roles, or groups this policy applies to
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

// RBACManager manages roles, permissions, and policies
type RBACManager interface {
	// Role management
	CreateRole(role *Role) error
	GetRole(name string) (*Role, error)
	UpdateRole(role *Role) error
	DeleteRole(name string) error
	ListRoles() ([]*Role, error)
	
	// Policy management
	CreatePolicy(policy *Policy) error
	GetPolicy(name string) (*Policy, error)
	UpdatePolicy(policy *Policy) error
	DeletePolicy(name string) error
	ListPolicies() ([]*Policy, error)
	
	// Permission checking
	HasPermission(user *UserIdentity, resource, action, target string) bool
	GetUserPermissions(user *UserIdentity) []Permission
	
	// Bulk operations
	AssignRoleToUser(userID, roleName string) error
	RemoveRoleFromUser(userID, roleName string) error
	GetUserRoles(userID string) ([]string, error)
}

// InMemoryRBAC implements RBACManager with in-memory storage
type InMemoryRBAC struct {
	roles     map[string]*Role
	policies  map[string]*Policy
	userRoles map[string][]string // userID -> roleNames
	mu        sync.RWMutex
}

// NewInMemoryRBAC creates a new in-memory RBAC manager
func NewInMemoryRBAC() *InMemoryRBAC {
	rbac := &InMemoryRBAC{
		roles:     make(map[string]*Role),
		policies:  make(map[string]*Policy),
		userRoles: make(map[string][]string),
	}
	
	// Initialize with default roles
	rbac.initializeDefaultRoles()
	
	return rbac
}

// initializeDefaultRoles creates default system roles
func (r *InMemoryRBAC) initializeDefaultRoles() {
	now := time.Now()
	
	// Admin role - full access
	adminRole := &Role{
		Name:        "admin",
		Description: "Full administrative access",
		Permissions: []Permission{
			{Resource: "*", Action: "*", Target: "*", Description: "Full access to all resources"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	
	// User role - basic access
	userRole := &Role{
		Name:        "user",
		Description: "Basic user access",
		Permissions: []Permission{
			{Resource: "tools", Action: "list", Target: "*", Description: "List all tools"},
			{Resource: "tools", Action: "call", Target: "*", Description: "Call any tool"},
			{Resource: "resources", Action: "list", Target: "*", Description: "List all resources"},
			{Resource: "resources", Action: "read", Target: "*", Description: "Read any resource"},
			{Resource: "prompts", Action: "list", Target: "*", Description: "List all prompts"},
			{Resource: "prompts", Action: "get", Target: "*", Description: "Get any prompt"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	
	// Read-only role - view access only
	readOnlyRole := &Role{
		Name:        "readonly",
		Description: "Read-only access",
		Permissions: []Permission{
			{Resource: "tools", Action: "list", Target: "*", Description: "List all tools"},
			{Resource: "resources", Action: "list", Target: "*", Description: "List all resources"},
			{Resource: "resources", Action: "read", Target: "*", Description: "Read any resource"},
			{Resource: "prompts", Action: "list", Target: "*", Description: "List all prompts"},
			{Resource: "prompts", Action: "get", Target: "*", Description: "Get any prompt"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	
	// Anonymous role - minimal access
	anonymousRole := &Role{
		Name:        "anonymous",
		Description: "Anonymous user access",
		Permissions: []Permission{
			{Resource: "tools", Action: "list", Target: "*", Description: "List all tools"},
			{Resource: "resources", Action: "list", Target: "*", Description: "List all resources"},
			{Resource: "prompts", Action: "list", Target: "*", Description: "List all prompts"},
		},
		CreatedAt: now,
		UpdatedAt: now,
	}
	
	r.roles["admin"] = adminRole
	r.roles["user"] = userRole
	r.roles["readonly"] = readOnlyRole
	r.roles["anonymous"] = anonymousRole
}

// CreateRole creates a new role
func (r *InMemoryRBAC) CreateRole(role *Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.roles[role.Name]; exists {
		return fmt.Errorf("role %s already exists", role.Name)
	}
	
	now := time.Now()
	role.CreatedAt = now
	role.UpdatedAt = now
	
	r.roles[role.Name] = role
	return nil
}

// GetRole retrieves a role by name
func (r *InMemoryRBAC) GetRole(name string) (*Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	role, exists := r.roles[name]
	if !exists {
		return nil, fmt.Errorf("role %s not found", name)
	}
	
	return role, nil
}

// UpdateRole updates an existing role
func (r *InMemoryRBAC) UpdateRole(role *Role) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.roles[role.Name]; !exists {
		return fmt.Errorf("role %s not found", role.Name)
	}
	
	role.UpdatedAt = time.Now()
	r.roles[role.Name] = role
	return nil
}

// DeleteRole deletes a role
func (r *InMemoryRBAC) DeleteRole(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Don't allow deletion of system roles
	if name == "admin" || name == "user" || name == "readonly" || name == "anonymous" {
		return fmt.Errorf("cannot delete system role %s", name)
	}
	
	delete(r.roles, name)
	return nil
}

// ListRoles returns all roles
func (r *InMemoryRBAC) ListRoles() ([]*Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	roles := make([]*Role, 0, len(r.roles))
	for _, role := range r.roles {
		roles = append(roles, role)
	}
	
	return roles, nil
}

// CreatePolicy creates a new policy
func (r *InMemoryRBAC) CreatePolicy(policy *Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.policies[policy.Name]; exists {
		return fmt.Errorf("policy %s already exists", policy.Name)
	}
	
	now := time.Now()
	policy.CreatedAt = now
	policy.UpdatedAt = now
	
	r.policies[policy.Name] = policy
	return nil
}

// GetPolicy retrieves a policy by name
func (r *InMemoryRBAC) GetPolicy(name string) (*Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	policy, exists := r.policies[name]
	if !exists {
		return nil, fmt.Errorf("policy %s not found", name)
	}
	
	return policy, nil
}

// UpdatePolicy updates an existing policy
func (r *InMemoryRBAC) UpdatePolicy(policy *Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	if _, exists := r.policies[policy.Name]; !exists {
		return fmt.Errorf("policy %s not found", policy.Name)
	}
	
	policy.UpdatedAt = time.Now()
	r.policies[policy.Name] = policy
	return nil
}

// DeletePolicy deletes a policy
func (r *InMemoryRBAC) DeletePolicy(name string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	delete(r.policies, name)
	return nil
}

// ListPolicies returns all policies
func (r *InMemoryRBAC) ListPolicies() ([]*Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	policies := make([]*Policy, 0, len(r.policies))
	for _, policy := range r.policies {
		policies = append(policies, policy)
	}
	
	return policies, nil
}

// HasPermission checks if user has permission for resource/action/target
func (r *InMemoryRBAC) HasPermission(user *UserIdentity, resource, action, target string) bool {
	if user == nil {
		return false
	}
	
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	// Check policies first (they can deny access)
	if r.checkPolicies(user, resource, action, target) == "deny" {
		return false
	}
	
	// Check role-based permissions
	allRoles := r.getAllUserRoles(user)
	
	for _, roleName := range allRoles {
		role, exists := r.roles[roleName]
		if !exists {
			continue
		}
		
		if r.checkRolePermissions(role, resource, action, target) {
			return true
		}
		
		// Check inherited roles
		for _, inheritedRole := range role.Inherits {
			if inherited, exists := r.roles[inheritedRole]; exists {
				if r.checkRolePermissions(inherited, resource, action, target) {
					return true
				}
			}
		}
	}
	
	return false
}

// getAllUserRoles gets all roles for a user (from identity + explicit assignments)
func (r *InMemoryRBAC) getAllUserRoles(user *UserIdentity) []string {
	roles := make(map[string]bool)
	
	// Add roles from user identity
	for _, role := range user.Roles {
		roles[role] = true
	}
	
	// Add explicitly assigned roles
	if userRoles, exists := r.userRoles[user.ID]; exists {
		for _, role := range userRoles {
			roles[role] = true
		}
	}
	
	// Convert to slice
	result := make([]string, 0, len(roles))
	for role := range roles {
		result = append(result, role)
	}
	
	return result
}

// checkPolicies evaluates policies for the user
func (r *InMemoryRBAC) checkPolicies(user *UserIdentity, resource, action, target string) string {
	// Sort policies by priority (higher first)
	var applicablePolicies []*Policy
	for _, policy := range r.policies {
		if r.policyAppliesTo(policy, user) {
			applicablePolicies = append(applicablePolicies, policy)
		}
	}
	
	// Check policies in priority order
	for _, policy := range applicablePolicies {
		for _, rule := range policy.Rules {
			if r.matchesRule(&rule, resource, action, target) {
				return rule.Effect
			}
		}
	}
	
	return "allow" // Default allow if no policies match
}

// policyAppliesTo checks if a policy applies to the user
func (r *InMemoryRBAC) policyAppliesTo(policy *Policy, user *UserIdentity) bool {
	if len(policy.Subjects) == 0 {
		return true // Policy applies to everyone
	}
	
	for _, subject := range policy.Subjects {
		if subject == "*" || subject == user.ID || subject == user.Username {
			return true
		}
		
		// Check if subject is a role
		for _, userRole := range user.Roles {
			if subject == userRole {
				return true
			}
		}
		
		// Check if subject is a group
		for _, userGroup := range user.Groups {
			if subject == userGroup {
				return true
			}
		}
	}
	
	return false
}

// checkRolePermissions checks if a role has the required permission
func (r *InMemoryRBAC) checkRolePermissions(role *Role, resource, action, target string) bool {
	for _, perm := range role.Permissions {
		if r.matchesPermission(&perm, resource, action, target) {
			return true
		}
	}
	return false
}

// matchesPermission checks if a permission matches the request
func (r *InMemoryRBAC) matchesPermission(perm *Permission, resource, action, target string) bool {
	return r.matchesPattern(perm.Resource, resource) &&
		r.matchesPattern(perm.Action, action) &&
		r.matchesPattern(perm.Target, target)
}

// matchesRule checks if a policy rule matches the request
func (r *InMemoryRBAC) matchesRule(rule *PolicyRule, resource, action, target string) bool {
	return r.matchesPattern(rule.Resource, resource) &&
		r.matchesPattern(rule.Action, action) &&
		r.matchesPattern(rule.Target, target)
}

// matchesPattern checks if a pattern matches a value (supports wildcards)
func (r *InMemoryRBAC) matchesPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	
	if pattern == value {
		return true
	}
	
	// Support simple wildcard patterns
	if strings.Contains(pattern, "*") {
		regexPattern := strings.ReplaceAll(pattern, "*", ".*")
		if matched, _ := regexp.MatchString("^"+regexPattern+"$", value); matched {
			return true
		}
	}
	
	return false
}

// GetUserPermissions returns all effective permissions for a user
func (r *InMemoryRBAC) GetUserPermissions(user *UserIdentity) []Permission {
	if user == nil {
		return nil
	}
	
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	var permissions []Permission
	allRoles := r.getAllUserRoles(user)
	
	for _, roleName := range allRoles {
		role, exists := r.roles[roleName]
		if !exists {
			continue
		}
		
		permissions = append(permissions, role.Permissions...)
		
		// Add permissions from inherited roles
		for _, inheritedRole := range role.Inherits {
			if inherited, exists := r.roles[inheritedRole]; exists {
				permissions = append(permissions, inherited.Permissions...)
			}
		}
	}
	
	return permissions
}

// AssignRoleToUser assigns a role to a user
func (r *InMemoryRBAC) AssignRoleToUser(userID, roleName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	// Check if role exists
	if _, exists := r.roles[roleName]; !exists {
		return fmt.Errorf("role %s not found", roleName)
	}
	
	if r.userRoles[userID] == nil {
		r.userRoles[userID] = []string{}
	}
	
	// Check if already assigned
	for _, existing := range r.userRoles[userID] {
		if existing == roleName {
			return nil // Already assigned
		}
	}
	
	r.userRoles[userID] = append(r.userRoles[userID], roleName)
	return nil
}

// RemoveRoleFromUser removes a role from a user
func (r *InMemoryRBAC) RemoveRoleFromUser(userID, roleName string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	
	userRoles := r.userRoles[userID]
	if userRoles == nil {
		return nil
	}
	
	var newRoles []string
	for _, existing := range userRoles {
		if existing != roleName {
			newRoles = append(newRoles, existing)
		}
	}
	
	r.userRoles[userID] = newRoles
	return nil
}

// GetUserRoles returns all roles assigned to a user
func (r *InMemoryRBAC) GetUserRoles(userID string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	
	if roles, exists := r.userRoles[userID]; exists {
		return roles, nil
	}
	
	return []string{}, nil
}