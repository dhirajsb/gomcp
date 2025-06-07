package auth

import (
	"sync"
	"sync/atomic"
	"time"
)

// AuthMetrics provides authentication performance metrics
type AuthMetrics struct {
	// Authentication counters
	AuthAttempts     int64 `json:"auth_attempts"`
	AuthSuccesses    int64 `json:"auth_successes"`
	AuthFailures     int64 `json:"auth_failures"`
	TokenValidations int64 `json:"token_validations"`

	// Authorization counters
	PermissionChecks  int64 `json:"permission_checks"`
	PermissionGrants  int64 `json:"permission_grants"`
	PermissionDenials int64 `json:"permission_denials"`
	PolicyEvaluations int64 `json:"policy_evaluations"`

	// Performance timing (in nanoseconds)
	AuthLatencySum   int64 `json:"auth_latency_sum_ns"`
	AuthLatencyCount int64 `json:"auth_latency_count"`
	PermLatencySum   int64 `json:"perm_latency_sum_ns"`
	PermLatencyCount int64 `json:"perm_latency_count"`

	// Error tracking
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error"`
	LastErrorTime time.Time `json:"last_error_time"`

	// Session tracking
	ActiveSessions  int64 `json:"active_sessions"`
	SessionsCreated int64 `json:"sessions_created"`
	SessionsExpired int64 `json:"sessions_expired"`

	// Provider-specific metrics
	ProviderMetrics map[string]*ProviderMetrics `json:"provider_metrics"`

	// Start time for uptime calculation
	StartTime time.Time `json:"start_time"`

	mu sync.RWMutex
}

// ProviderMetrics tracks metrics for individual auth providers
type ProviderMetrics struct {
	Name          string    `json:"name"`
	Type          string    `json:"type"`
	AuthAttempts  int64     `json:"auth_attempts"`
	AuthSuccesses int64     `json:"auth_successes"`
	AuthFailures  int64     `json:"auth_failures"`
	AvgLatency    float64   `json:"avg_latency_ms"`
	LastAuth      time.Time `json:"last_auth"`
	ErrorRate     float64   `json:"error_rate"`
}

// RBACMetrics provides RBAC performance metrics
type RBACMetrics struct {
	// Role operations
	RoleCreations int64 `json:"role_creations"`
	RoleUpdates   int64 `json:"role_updates"`
	RoleDeletions int64 `json:"role_deletions"`
	RoleLookups   int64 `json:"role_lookups"`

	// Policy operations
	PolicyCreations   int64 `json:"policy_creations"`
	PolicyUpdates     int64 `json:"policy_updates"`
	PolicyDeletions   int64 `json:"policy_deletions"`
	PolicyEvaluations int64 `json:"policy_evaluations"`

	// Permission checks
	PermissionChecks  int64 `json:"permission_checks"`
	PermissionGrants  int64 `json:"permission_grants"`
	PermissionDenials int64 `json:"permission_denials"`

	// Performance timing
	RoleLatencySum     int64 `json:"role_latency_sum_ns"`
	RoleLatencyCount   int64 `json:"role_latency_count"`
	PolicyLatencySum   int64 `json:"policy_latency_sum_ns"`
	PolicyLatencyCount int64 `json:"policy_latency_count"`
	PermLatencySum     int64 `json:"perm_latency_sum_ns"`
	PermLatencyCount   int64 `json:"perm_latency_count"`

	// Cache metrics
	RoleCacheHits     int64 `json:"role_cache_hits"`
	RoleCacheMisses   int64 `json:"role_cache_misses"`
	PolicyCacheHits   int64 `json:"policy_cache_hits"`
	PolicyCacheMisses int64 `json:"policy_cache_misses"`

	StartTime time.Time `json:"start_time"`
}

// NewAuthMetrics creates a new auth metrics instance
func NewAuthMetrics() *AuthMetrics {
	return &AuthMetrics{
		ProviderMetrics: make(map[string]*ProviderMetrics),
		StartTime:       time.Now(),
	}
}

// NewRBACMetrics creates a new RBAC metrics instance
func NewRBACMetrics() *RBACMetrics {
	return &RBACMetrics{
		StartTime: time.Now(),
	}
}

// RecordAuthAttempt records an authentication attempt
func (m *AuthMetrics) RecordAuthAttempt(provider string, success bool, latency time.Duration) {
	atomic.AddInt64(&m.AuthAttempts, 1)

	if success {
		atomic.AddInt64(&m.AuthSuccesses, 1)
	} else {
		atomic.AddInt64(&m.AuthFailures, 1)
	}

	// Record timing
	atomic.AddInt64(&m.AuthLatencySum, int64(latency))
	atomic.AddInt64(&m.AuthLatencyCount, 1)

	// Update provider metrics
	m.updateProviderMetrics(provider, success, latency)
}

// RecordTokenValidation records a token validation
func (m *AuthMetrics) RecordTokenValidation() {
	atomic.AddInt64(&m.TokenValidations, 1)
}

// RecordPermissionCheck records a permission check
func (m *AuthMetrics) RecordPermissionCheck(granted bool, latency time.Duration) {
	atomic.AddInt64(&m.PermissionChecks, 1)

	if granted {
		atomic.AddInt64(&m.PermissionGrants, 1)
	} else {
		atomic.AddInt64(&m.PermissionDenials, 1)
	}

	// Record timing
	atomic.AddInt64(&m.PermLatencySum, int64(latency))
	atomic.AddInt64(&m.PermLatencyCount, 1)
}

// RecordPolicyEvaluation records a policy evaluation
func (m *AuthMetrics) RecordPolicyEvaluation() {
	atomic.AddInt64(&m.PolicyEvaluations, 1)
}

// RecordError records an authentication error
func (m *AuthMetrics) RecordError(err error) {
	atomic.AddInt64(&m.ErrorCount, 1)

	m.mu.Lock()
	m.LastError = err.Error()
	m.LastErrorTime = time.Now()
	m.mu.Unlock()
}

// RecordSessionCreated records a new session
func (m *AuthMetrics) RecordSessionCreated() {
	atomic.AddInt64(&m.ActiveSessions, 1)
	atomic.AddInt64(&m.SessionsCreated, 1)
}

// RecordSessionExpired records an expired session
func (m *AuthMetrics) RecordSessionExpired() {
	atomic.AddInt64(&m.ActiveSessions, -1)
	atomic.AddInt64(&m.SessionsExpired, 1)
}

// updateProviderMetrics updates metrics for a specific provider
func (m *AuthMetrics) updateProviderMetrics(providerName string, success bool, latency time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	provider, exists := m.ProviderMetrics[providerName]
	if !exists {
		provider = &ProviderMetrics{
			Name: providerName,
			Type: providerName,
		}
		m.ProviderMetrics[providerName] = provider
	}

	provider.AuthAttempts++
	if success {
		provider.AuthSuccesses++
	} else {
		provider.AuthFailures++
	}

	// Update average latency
	if provider.AuthAttempts > 0 {
		provider.AvgLatency = float64(latency.Nanoseconds()) / 1000000.0 // Convert to ms
	}

	provider.LastAuth = time.Now()

	// Calculate error rate
	if provider.AuthAttempts > 0 {
		provider.ErrorRate = float64(provider.AuthFailures) / float64(provider.AuthAttempts)
	}
}

// GetStats returns current authentication statistics
func (m *AuthMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	authAttempts := atomic.LoadInt64(&m.AuthAttempts)
	authSuccesses := atomic.LoadInt64(&m.AuthSuccesses)
	authFailures := atomic.LoadInt64(&m.AuthFailures)
	permChecks := atomic.LoadInt64(&m.PermissionChecks)
	permGrants := atomic.LoadInt64(&m.PermissionGrants)
	permDenials := atomic.LoadInt64(&m.PermissionDenials)

	// Calculate rates
	var successRate, permissionGrantRate float64
	if authAttempts > 0 {
		successRate = float64(authSuccesses) / float64(authAttempts)
	}
	if permChecks > 0 {
		permissionGrantRate = float64(permGrants) / float64(permChecks)
	}

	// Calculate average latencies
	var avgAuthLatency, avgPermLatency float64
	if count := atomic.LoadInt64(&m.AuthLatencyCount); count > 0 {
		avgAuthLatency = float64(atomic.LoadInt64(&m.AuthLatencySum)) / float64(count) / 1000000.0 // Convert to ms
	}
	if count := atomic.LoadInt64(&m.PermLatencyCount); count > 0 {
		avgPermLatency = float64(atomic.LoadInt64(&m.PermLatencySum)) / float64(count) / 1000000.0 // Convert to ms
	}

	return map[string]interface{}{
		"auth_attempts":         authAttempts,
		"auth_successes":        authSuccesses,
		"auth_failures":         authFailures,
		"auth_success_rate":     successRate,
		"token_validations":     atomic.LoadInt64(&m.TokenValidations),
		"permission_checks":     permChecks,
		"permission_grants":     permGrants,
		"permission_denials":    permDenials,
		"permission_grant_rate": permissionGrantRate,
		"policy_evaluations":    atomic.LoadInt64(&m.PolicyEvaluations),
		"avg_auth_latency_ms":   avgAuthLatency,
		"avg_perm_latency_ms":   avgPermLatency,
		"error_count":           atomic.LoadInt64(&m.ErrorCount),
		"last_error":            m.LastError,
		"last_error_time":       m.LastErrorTime,
		"active_sessions":       atomic.LoadInt64(&m.ActiveSessions),
		"sessions_created":      atomic.LoadInt64(&m.SessionsCreated),
		"sessions_expired":      atomic.LoadInt64(&m.SessionsExpired),
		"uptime":                time.Since(m.StartTime),
		"provider_metrics":      m.ProviderMetrics,
	}
}

// RBAC Metrics Methods

// RecordRoleOperation records a role operation
func (m *RBACMetrics) RecordRoleOperation(operation string, latency time.Duration) {
	switch operation {
	case "create":
		atomic.AddInt64(&m.RoleCreations, 1)
	case "update":
		atomic.AddInt64(&m.RoleUpdates, 1)
	case "delete":
		atomic.AddInt64(&m.RoleDeletions, 1)
	case "lookup":
		atomic.AddInt64(&m.RoleLookups, 1)
	}

	atomic.AddInt64(&m.RoleLatencySum, int64(latency))
	atomic.AddInt64(&m.RoleLatencyCount, 1)
}

// RecordPolicyOperation records a policy operation
func (m *RBACMetrics) RecordPolicyOperation(operation string, latency time.Duration) {
	switch operation {
	case "create":
		atomic.AddInt64(&m.PolicyCreations, 1)
	case "update":
		atomic.AddInt64(&m.PolicyUpdates, 1)
	case "delete":
		atomic.AddInt64(&m.PolicyDeletions, 1)
	case "evaluate":
		atomic.AddInt64(&m.PolicyEvaluations, 1)
	}

	atomic.AddInt64(&m.PolicyLatencySum, int64(latency))
	atomic.AddInt64(&m.PolicyLatencyCount, 1)
}

// RecordPermissionCheck records a permission check
func (m *RBACMetrics) RecordPermissionCheck(granted bool, latency time.Duration) {
	atomic.AddInt64(&m.PermissionChecks, 1)

	if granted {
		atomic.AddInt64(&m.PermissionGrants, 1)
	} else {
		atomic.AddInt64(&m.PermissionDenials, 1)
	}

	atomic.AddInt64(&m.PermLatencySum, int64(latency))
	atomic.AddInt64(&m.PermLatencyCount, 1)
}

// RecordCacheHit records a cache hit/miss
func (m *RBACMetrics) RecordCacheHit(cacheType string, hit bool) {
	switch cacheType {
	case "role":
		if hit {
			atomic.AddInt64(&m.RoleCacheHits, 1)
		} else {
			atomic.AddInt64(&m.RoleCacheMisses, 1)
		}
	case "policy":
		if hit {
			atomic.AddInt64(&m.PolicyCacheHits, 1)
		} else {
			atomic.AddInt64(&m.PolicyCacheMisses, 1)
		}
	}
}

// GetStats returns current RBAC statistics
func (m *RBACMetrics) GetStats() map[string]interface{} {
	permChecks := atomic.LoadInt64(&m.PermissionChecks)
	permGrants := atomic.LoadInt64(&m.PermissionGrants)
	roleCacheHits := atomic.LoadInt64(&m.RoleCacheHits)
	roleCacheMisses := atomic.LoadInt64(&m.RoleCacheMisses)
	policyCacheHits := atomic.LoadInt64(&m.PolicyCacheHits)
	policyCacheMisses := atomic.LoadInt64(&m.PolicyCacheMisses)

	// Calculate rates
	var permissionGrantRate, roleCacheHitRate, policyCacheHitRate float64
	if permChecks > 0 {
		permissionGrantRate = float64(permGrants) / float64(permChecks)
	}
	if totalRoleCache := roleCacheHits + roleCacheMisses; totalRoleCache > 0 {
		roleCacheHitRate = float64(roleCacheHits) / float64(totalRoleCache)
	}
	if totalPolicyCache := policyCacheHits + policyCacheMisses; totalPolicyCache > 0 {
		policyCacheHitRate = float64(policyCacheHits) / float64(totalPolicyCache)
	}

	// Calculate average latencies
	var avgRoleLatency, avgPolicyLatency, avgPermLatency float64
	if count := atomic.LoadInt64(&m.RoleLatencyCount); count > 0 {
		avgRoleLatency = float64(atomic.LoadInt64(&m.RoleLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.PolicyLatencyCount); count > 0 {
		avgPolicyLatency = float64(atomic.LoadInt64(&m.PolicyLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.PermLatencyCount); count > 0 {
		avgPermLatency = float64(atomic.LoadInt64(&m.PermLatencySum)) / float64(count) / 1000000.0
	}

	return map[string]interface{}{
		"role_creations":        atomic.LoadInt64(&m.RoleCreations),
		"role_updates":          atomic.LoadInt64(&m.RoleUpdates),
		"role_deletions":        atomic.LoadInt64(&m.RoleDeletions),
		"role_lookups":          atomic.LoadInt64(&m.RoleLookups),
		"policy_creations":      atomic.LoadInt64(&m.PolicyCreations),
		"policy_updates":        atomic.LoadInt64(&m.PolicyUpdates),
		"policy_deletions":      atomic.LoadInt64(&m.PolicyDeletions),
		"policy_evaluations":    atomic.LoadInt64(&m.PolicyEvaluations),
		"permission_checks":     permChecks,
		"permission_grants":     permGrants,
		"permission_denials":    atomic.LoadInt64(&m.PermissionDenials),
		"permission_grant_rate": permissionGrantRate,
		"avg_role_latency_ms":   avgRoleLatency,
		"avg_policy_latency_ms": avgPolicyLatency,
		"avg_perm_latency_ms":   avgPermLatency,
		"role_cache_hits":       roleCacheHits,
		"role_cache_misses":     roleCacheMisses,
		"role_cache_hit_rate":   roleCacheHitRate,
		"policy_cache_hits":     policyCacheHits,
		"policy_cache_misses":   policyCacheMisses,
		"policy_cache_hit_rate": policyCacheHitRate,
		"uptime":                time.Since(m.StartTime),
	}
}
