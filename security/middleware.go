package security

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/dhirajsb/gomcp/types"
)

// SecurityMiddleware provides security validation for MCP requests
type SecurityMiddleware struct {
	validator       *SecurityValidatorManager
	config          SecurityMiddlewareConfig
	auditLogger     AuditLogger
	rateLimit       RateLimiter
	requestFilter   RequestFilter
}

// SecurityMiddlewareConfig holds security middleware configuration
type SecurityMiddlewareConfig struct {
	Enabled           bool                   `json:"enabled"`
	ValidateInput     bool                   `json:"validate_input"`
	ValidateOutput    bool                   `json:"validate_output"`
	AutoSanitize      bool                   `json:"auto_sanitize"`
	BlockOnViolation  bool                   `json:"block_on_violation"`
	AuditLogging      bool                   `json:"audit_logging"`
	RateLimiting      bool                   `json:"rate_limiting"`
	ContentFiltering  bool                   `json:"content_filtering"`
	MaxRequestSize    int64                  `json:"max_request_size"`
	AllowedMethods    []string               `json:"allowed_methods"`
	AllowedOrigins    []string               `json:"allowed_origins"`
	RequireHTTPS      bool                   `json:"require_https"`
	CSPHeader         string                 `json:"csp_header"`
	Config            map[string]interface{} `json:"config"`
}

// AuditLogger defines the interface for security audit logging
type AuditLogger interface {
	LogSecurityEvent(ctx context.Context, event SecurityEvent) error
}

// SecurityEvent represents a security-related event
type SecurityEvent struct {
	Timestamp    time.Time              `json:"timestamp"`
	EventType    string                 `json:"event_type"`
	Severity     SecurityLevel          `json:"severity"`
	UserID       string                 `json:"user_id"`
	SessionID    string                 `json:"session_id"`
	RequestID    string                 `json:"request_id"`
	RemoteAddr   string                 `json:"remote_addr"`
	UserAgent    string                 `json:"user_agent"`
	Method       string                 `json:"method"`
	URI          string                 `json:"uri"`
	Violations   []SecurityViolation    `json:"violations"`
	Action       string                 `json:"action"`        // "allowed", "blocked", "sanitized"
	Message      string                 `json:"message"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// RateLimiter defines the interface for rate limiting
type RateLimiter interface {
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
	GetUsage(ctx context.Context, key string) (int, error)
}

// RequestFilter defines the interface for request filtering
type RequestFilter interface {
	ShouldFilter(ctx context.Context, req *http.Request) bool
	FilterRequest(ctx context.Context, req *http.Request) (*http.Request, error)
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(config SecurityMiddlewareConfig, validator *SecurityValidatorManager) *SecurityMiddleware {
	return &SecurityMiddleware{
		validator: validator,
		config:    config,
	}
}

// SetAuditLogger sets the audit logger
func (sm *SecurityMiddleware) SetAuditLogger(logger AuditLogger) {
	sm.auditLogger = logger
}

// SetRateLimiter sets the rate limiter
func (sm *SecurityMiddleware) SetRateLimiter(limiter RateLimiter) {
	sm.rateLimit = limiter
}

// SetRequestFilter sets the request filter
func (sm *SecurityMiddleware) SetRequestFilter(filter RequestFilter) {
	sm.requestFilter = filter
}

// HTTPMiddleware returns an HTTP middleware function
func (sm *SecurityMiddleware) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !sm.config.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		
		ctx := r.Context()
		
		// Apply security headers
		sm.applySecurityHeaders(w, r)
		
		// Check HTTPS requirement
		if sm.config.RequireHTTPS && r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			sm.logSecurityEvent(ctx, SecurityEvent{
				EventType:  "https_required",
				Severity:   SecurityLevelMedium,
				RemoteAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Method:     r.Method,
				URI:        r.RequestURI,
				Action:     "blocked",
				Message:    "HTTPS required but request is not secure",
			})
			
			http.Error(w, "HTTPS required", http.StatusBadRequest)
			return
		}
		
		// Check request size
		if sm.config.MaxRequestSize > 0 && r.ContentLength > sm.config.MaxRequestSize {
			sm.logSecurityEvent(ctx, SecurityEvent{
				EventType:  "request_too_large",
				Severity:   SecurityLevelMedium,
				RemoteAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Method:     r.Method,
				URI:        r.RequestURI,
				Action:     "blocked",
				Message:    fmt.Sprintf("Request size %d exceeds limit %d", r.ContentLength, sm.config.MaxRequestSize),
			})
			
			http.Error(w, "Request too large", http.StatusRequestEntityTooLarge)
			return
		}
		
		// Check allowed methods
		if len(sm.config.AllowedMethods) > 0 && !sm.isMethodAllowed(r.Method) {
			sm.logSecurityEvent(ctx, SecurityEvent{
				EventType:  "method_not_allowed",
				Severity:   SecurityLevelMedium,
				RemoteAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Method:     r.Method,
				URI:        r.RequestURI,
				Action:     "blocked",
				Message:    fmt.Sprintf("Method %s not allowed", r.Method),
			})
			
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		
		// Check allowed origins
		if len(sm.config.AllowedOrigins) > 0 && !sm.isOriginAllowed(r.Header.Get("Origin")) {
			sm.logSecurityEvent(ctx, SecurityEvent{
				EventType:  "origin_not_allowed",
				Severity:   SecurityLevelMedium,
				RemoteAddr: r.RemoteAddr,
				UserAgent:  r.UserAgent(),
				Method:     r.Method,
				URI:        r.RequestURI,
				Action:     "blocked",
				Message:    fmt.Sprintf("Origin %s not allowed", r.Header.Get("Origin")),
			})
			
			http.Error(w, "Origin not allowed", http.StatusForbidden)
			return
		}
		
		// Rate limiting
		if sm.config.RateLimiting && sm.rateLimit != nil {
			if allowed, err := sm.rateLimit.Allow(ctx, r.RemoteAddr, 100, time.Hour); err == nil && !allowed {
				sm.logSecurityEvent(ctx, SecurityEvent{
					EventType:  "rate_limit_exceeded",
					Severity:   SecurityLevelMedium,
					RemoteAddr: r.RemoteAddr,
					UserAgent:  r.UserAgent(),
					Method:     r.Method,
					URI:        r.RequestURI,
					Action:     "blocked",
					Message:    "Rate limit exceeded",
				})
				
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}
		
		// Request filtering
		if sm.config.ContentFiltering && sm.requestFilter != nil {
			if sm.requestFilter.ShouldFilter(ctx, r) {
				filtered, err := sm.requestFilter.FilterRequest(ctx, r)
				if err != nil {
					sm.logSecurityEvent(ctx, SecurityEvent{
						EventType:  "request_filter_error",
						Severity:   SecurityLevelHigh,
						RemoteAddr: r.RemoteAddr,
						UserAgent:  r.UserAgent(),
						Method:     r.Method,
						URI:        r.RequestURI,
						Action:     "blocked",
						Message:    fmt.Sprintf("Request filtering failed: %v", err),
					})
					
					http.Error(w, "Request filtered", http.StatusBadRequest)
					return
				}
				r = filtered
			}
		}
		
		next.ServeHTTP(w, r)
	})
}

// ValidateMCPRequest validates an MCP request
func (sm *SecurityMiddleware) ValidateMCPRequest(ctx context.Context, req *types.Request) (*ValidationResult, error) {
	if !sm.config.Enabled || !sm.config.ValidateInput {
		return &ValidationResult{Valid: true, Score: 100}, nil
	}
	
	// Extract input parameters
	input := make(map[string]interface{})
	
	// Add method
	input["method"] = req.Method
	
	// Add parameters if present
	if req.Params != nil {
		// Convert params to map
		if paramsBytes, err := json.Marshal(req.Params); err == nil {
			var paramsMap map[string]interface{}
			if json.Unmarshal(paramsBytes, &paramsMap) == nil {
				for k, v := range paramsMap {
					input[k] = v
				}
			}
		}
	}
	
	// Validate input
	result, err := sm.validator.ValidateInput(ctx, input)
	if err != nil {
		return nil, err
	}
	
	// Log security events
	if len(result.Violations) > 0 {
		event := SecurityEvent{
			Timestamp:  time.Now(),
			EventType:  "input_validation",
			Severity:   sm.getMaxSeverity(result.Violations),
			RequestID:  sm.getRequestID(ctx),
			UserID:     sm.getUserID(ctx),
			SessionID:  sm.getSessionID(ctx),
			Method:     req.Method,
			Violations: result.Violations,
			Message:    fmt.Sprintf("Input validation found %d violations", len(result.Violations)),
		}
		
		if result.Valid || !sm.config.BlockOnViolation {
			event.Action = "allowed"
		} else {
			event.Action = "blocked"
		}
		
		if sm.config.AutoSanitize && len(result.Sanitized) > 0 {
			event.Action = "sanitized"
		}
		
		sm.logSecurityEvent(ctx, event)
	}
	
	return result, nil
}

// ValidateMCPResponse validates an MCP response
func (sm *SecurityMiddleware) ValidateMCPResponse(ctx context.Context, resp *types.Response) (*ValidationResult, error) {
	if !sm.config.Enabled || !sm.config.ValidateOutput {
		return &ValidationResult{Valid: true, Score: 100}, nil
	}
	
	// Extract output data
	input := make(map[string]interface{})
	
	// Add result if present
	if resp.Result != nil {
		// Convert result to map
		if resultBytes, err := json.Marshal(resp.Result); err == nil {
			var resultMap map[string]interface{}
			if json.Unmarshal(resultBytes, &resultMap) == nil {
				for k, v := range resultMap {
					input[k] = v
				}
			}
		}
	}
	
	// Add error if present
	if resp.Error != nil {
		input["error_message"] = resp.Error.Message
		if resp.Error.Data != nil {
			input["error_data"] = resp.Error.Data
		}
	}
	
	// Validate output
	result, err := sm.validator.ValidateInput(ctx, input)
	if err != nil {
		return nil, err
	}
	
	// Log security events for output validation
	if len(result.Violations) > 0 {
		event := SecurityEvent{
			Timestamp:  time.Now(),
			EventType:  "output_validation",
			Severity:   sm.getMaxSeverity(result.Violations),
			RequestID:  sm.getRequestID(ctx),
			UserID:     sm.getUserID(ctx),
			SessionID:  sm.getSessionID(ctx),
			Violations: result.Violations,
			Action:     "sanitized",
			Message:    fmt.Sprintf("Output validation found %d violations", len(result.Violations)),
		}
		
		sm.logSecurityEvent(ctx, event)
	}
	
	return result, nil
}

// applySecurityHeaders applies security headers to the response
func (sm *SecurityMiddleware) applySecurityHeaders(w http.ResponseWriter, r *http.Request) {
	headers := w.Header()
	
	// Basic security headers
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("X-XSS-Protection", "1; mode=block")
	headers.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	
	// HSTS for HTTPS
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}
	
	// CSP header if configured
	if sm.config.CSPHeader != "" {
		headers.Set("Content-Security-Policy", sm.config.CSPHeader)
	} else {
		// Default restrictive CSP
		headers.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
	}
	
	// CORS headers for allowed origins
	origin := r.Header.Get("Origin")
	if sm.isOriginAllowed(origin) {
		headers.Set("Access-Control-Allow-Origin", origin)
		headers.Set("Access-Control-Allow-Credentials", "true")
		headers.Set("Access-Control-Allow-Methods", strings.Join(sm.config.AllowedMethods, ", "))
		headers.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
	}
}

// isMethodAllowed checks if HTTP method is allowed
func (sm *SecurityMiddleware) isMethodAllowed(method string) bool {
	if len(sm.config.AllowedMethods) == 0 {
		return true
	}
	
	for _, allowed := range sm.config.AllowedMethods {
		if strings.EqualFold(method, allowed) {
			return true
		}
	}
	
	return false
}

// isOriginAllowed checks if origin is allowed
func (sm *SecurityMiddleware) isOriginAllowed(origin string) bool {
	if len(sm.config.AllowedOrigins) == 0 {
		return true
	}
	
	if origin == "" {
		return true // Allow requests without origin header
	}
	
	for _, allowed := range sm.config.AllowedOrigins {
		if allowed == "*" || strings.EqualFold(origin, allowed) {
			return true
		}
	}
	
	return false
}

// getMaxSeverity returns the maximum severity level from violations
func (sm *SecurityMiddleware) getMaxSeverity(violations []SecurityViolation) SecurityLevel {
	maxSeverity := SecurityLevelInfo
	for _, violation := range violations {
		if violation.Level > maxSeverity {
			maxSeverity = violation.Level
		}
	}
	return maxSeverity
}

// logSecurityEvent logs a security event
func (sm *SecurityMiddleware) logSecurityEvent(ctx context.Context, event SecurityEvent) {
	if !sm.config.AuditLogging || sm.auditLogger == nil {
		return
	}
	
	event.Timestamp = time.Now()
	sm.auditLogger.LogSecurityEvent(ctx, event)
}

// Helper functions to extract context values
func (sm *SecurityMiddleware) getRequestID(ctx context.Context) string {
	if id := ctx.Value("request_id"); id != nil {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}
	return ""
}

func (sm *SecurityMiddleware) getUserID(ctx context.Context) string {
	if id := ctx.Value("user_id"); id != nil {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}
	return ""
}

func (sm *SecurityMiddleware) getSessionID(ctx context.Context) string {
	if id := ctx.Value("session_id"); id != nil {
		if idStr, ok := id.(string); ok {
			return idStr
		}
	}
	return ""
}

// Simple in-memory rate limiter implementation
type InMemoryRateLimiter struct {
	requests map[string][]time.Time
	mu       sync.RWMutex
}

// NewInMemoryRateLimiter creates a new in-memory rate limiter
func NewInMemoryRateLimiter() *InMemoryRateLimiter {
	return &InMemoryRateLimiter{
		requests: make(map[string][]time.Time),
	}
}

// Allow checks if request is allowed under rate limit
func (rl *InMemoryRateLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	now := time.Now()
	cutoff := now.Add(-window)
	
	// Get existing requests for key
	requests := rl.requests[key]
	
	// Remove old requests outside the window
	var validRequests []time.Time
	for _, reqTime := range requests {
		if reqTime.After(cutoff) {
			validRequests = append(validRequests, reqTime)
		}
	}
	
	// Check if limit exceeded
	if len(validRequests) >= limit {
		rl.requests[key] = validRequests
		return false, nil
	}
	
	// Add current request
	validRequests = append(validRequests, now)
	rl.requests[key] = validRequests
	
	return true, nil
}

// GetUsage returns current usage for key
func (rl *InMemoryRateLimiter) GetUsage(ctx context.Context, key string) (int, error) {
	rl.mu.RLock()
	defer rl.mu.RUnlock()
	
	requests := rl.requests[key]
	return len(requests), nil
}

// Simple audit logger implementation
type SimpleAuditLogger struct {
	logFunc func(event SecurityEvent)
}

// NewSimpleAuditLogger creates a new simple audit logger
func NewSimpleAuditLogger(logFunc func(event SecurityEvent)) *SimpleAuditLogger {
	return &SimpleAuditLogger{logFunc: logFunc}
}

// LogSecurityEvent logs a security event
func (al *SimpleAuditLogger) LogSecurityEvent(ctx context.Context, event SecurityEvent) error {
	if al.logFunc != nil {
		al.logFunc(event)
	}
	return nil
}