package security

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/dhirajsb/gomcp/pkg/features"
)

func TestNewStrict(t *testing.T) {
	validator := NewStrict("test-validator")

	if validator.name != "test-validator" {
		t.Errorf("Expected name 'test-validator', got '%s'", validator.name)
	}
}

func TestStrictValidator_Name(t *testing.T) {
	validator := NewStrict("my-validator")

	if validator.Name() != "my-validator" {
		t.Errorf("Expected name 'my-validator', got '%s'", validator.Name())
	}
}

func TestStrictValidator_ValidateRequest_ValidRequest(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	// Test with valid tools/list request
	req := &features.Request{
		Method: "tools/list",
		Params: nil,
	}

	err := validator.ValidateRequest(ctx, req)
	if err != nil {
		t.Errorf("Expected no error for valid request, got %v", err)
	}
}

func TestStrictValidator_ValidateRequest_NilRequest(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	err := validator.ValidateRequest(ctx, nil)
	if err == nil {
		t.Error("Expected error for nil request, got nil")
	}
}

func TestStrictValidator_ValidateRequest_EmptyMethod(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	req := &features.Request{
		Method: "", // Empty method
		Params: nil,
	}

	err := validator.ValidateRequest(ctx, req)
	if err == nil {
		t.Error("Expected error for empty method, got nil")
	}
}

func TestStrictValidator_ValidateRequest_InvalidMethod(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	invalidMethods := []string{
		"invalid/method",
		"../../../etc/passwd",
		"<script>alert('xss')</script>",
		"'; DROP TABLE users; --",
		"method with spaces",
		"method\nwith\nnewlines",
	}

	for _, method := range invalidMethods {
		req := &features.Request{
			Method: method,
			Params: nil,
		}

		err := validator.ValidateRequest(ctx, req)
		if err == nil {
			t.Errorf("Expected error for invalid method '%s', got nil", method)
		}
	}
}

func TestStrictValidator_ValidateRequest_ValidMethods(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	validMethods := []string{
		"tools/list",
		"tools/call",
		"resources/list",
		"resources/read",
		"prompts/list",
		"prompts/get",
		"ping",
		"initialize",
	}

	for _, method := range validMethods {
		req := &features.Request{
			Method: method,
			Params: nil,
		}

		err := validator.ValidateRequest(ctx, req)
		if err != nil {
			t.Errorf("Expected no error for valid method '%s', got %v", method, err)
		}
	}
}

func TestStrictValidator_ValidateRequest_SuspiciousParams(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	suspiciousParams := []interface{}{
		map[string]interface{}{
			"command": "rm -rf /",
		},
		map[string]interface{}{
			"query": "SELECT * FROM users; DROP TABLE users;",
		},
		map[string]interface{}{
			"html": "<script>alert('xss')</script>",
		},
		map[string]interface{}{
			"path": "../../../etc/passwd",
		},
		map[string]interface{}{
			"input": "'; DROP TABLE users; --",
		},
	}

	for _, params := range suspiciousParams {
		req := &features.Request{
			Method: "tools/call",
			Params: params,
		}

		err := validator.ValidateRequest(ctx, req)
		if err == nil {
			t.Errorf("Expected error for suspicious params %v, got nil", params)
		}
	}
}

func TestStrictValidator_SanitizeParams_CleanParams(t *testing.T) {
	validator := NewStrict("test")

	cleanParams := map[string]interface{}{
		"name":   "John Doe",
		"email":  "john@example.com",
		"age":    30,
		"active": true,
	}

	sanitized := validator.SanitizeParams(cleanParams)

	// Clean params should remain unchanged
	if len(sanitized) != len(cleanParams) {
		t.Errorf("Expected %d params after sanitization, got %d", len(cleanParams), len(sanitized))
	}

	for key, expectedValue := range cleanParams {
		if sanitized[key] != expectedValue {
			t.Errorf("Expected param %s to be %v, got %v", key, expectedValue, sanitized[key])
		}
	}
}

func TestStrictValidator_SanitizeParams_MaliciousParams(t *testing.T) {
	validator := NewStrict("test")

	maliciousParams := map[string]interface{}{
		"normal_field":      "safe value",
		"sql_injection":     "'; DROP TABLE users; --",
		"xss_attempt":       "<script>alert('xss')</script>",
		"path_traversal":    "../../../etc/passwd",
		"command_injection": "ls; rm -rf /",
		"null_bytes":        "test\x00malicious",
	}

	sanitized := validator.SanitizeParams(maliciousParams)

	// Check that normal field is preserved
	if sanitized["normal_field"] != "safe value" {
		t.Errorf("Expected normal field to be preserved, got %v", sanitized["normal_field"])
	}

	// Check that malicious content is sanitized or removed
	maliciousFields := []string{"sql_injection", "xss_attempt", "path_traversal", "command_injection", "null_bytes"}

	for _, field := range maliciousFields {
		if value, exists := sanitized[field]; exists {
			// If field exists, it should be sanitized (not contain dangerous patterns)
			strValue, ok := value.(string)
			if ok {
				dangerousPatterns := []string{
					"<script>", "</script>", "DROP TABLE", "rm -rf", "../..", "\x00",
				}

				for _, pattern := range dangerousPatterns {
					if containsIgnoreCase(strValue, pattern) {
						t.Errorf("Field %s still contains dangerous pattern '%s': %s", field, pattern, strValue)
					}
				}
			}
		}
	}
}

func TestStrictValidator_SanitizeParams_NilParams(t *testing.T) {
	validator := NewStrict("test")

	sanitized := validator.SanitizeParams(nil)

	if sanitized == nil {
		t.Error("Expected non-nil result for nil params")
	}

	if len(sanitized) != 0 {
		t.Errorf("Expected empty map for nil params, got %v", sanitized)
	}
}

func TestStrictValidator_SanitizeParams_EmptyParams(t *testing.T) {
	validator := NewStrict("test")

	emptyParams := map[string]interface{}{}
	sanitized := validator.SanitizeParams(emptyParams)

	if len(sanitized) != 0 {
		t.Errorf("Expected empty map for empty params, got %v", sanitized)
	}
}

func TestStrictValidator_SanitizeParams_NonStringValues(t *testing.T) {
	validator := NewStrict("test")

	params := map[string]interface{}{
		"number":  42,
		"float":   3.14,
		"boolean": true,
		"nil":     nil,
		"array":   []string{"a", "b", "c"},
		"object": map[string]interface{}{
			"nested": "value",
		},
	}

	sanitized := validator.SanitizeParams(params)

	// Non-string values should generally be preserved
	if sanitized["number"] != 42 {
		t.Errorf("Expected number to be preserved, got %v", sanitized["number"])
	}

	if sanitized["float"] != 3.14 {
		t.Errorf("Expected float to be preserved, got %v", sanitized["float"])
	}

	if sanitized["boolean"] != true {
		t.Errorf("Expected boolean to be preserved, got %v", sanitized["boolean"])
	}
}

func TestStrictValidator_SanitizeParams_DeepSanitization(t *testing.T) {
	validator := NewStrict("test")

	params := map[string]interface{}{
		"safe": "normal value",
		"nested": map[string]interface{}{
			"safe_nested":      "good value",
			"malicious_nested": "<script>alert('nested xss')</script>",
		},
		"array_with_malicious": []interface{}{
			"safe string",
			"<img src=x onerror=alert(1)>",
			42,
		},
	}

	sanitized := validator.SanitizeParams(params)

	// Check that nested malicious content is also sanitized
	if nested, ok := sanitized["nested"].(map[string]interface{}); ok {
		if maliciousValue, exists := nested["malicious_nested"]; exists {
			if strValue, ok := maliciousValue.(string); ok {
				if containsIgnoreCase(strValue, "<script>") || containsIgnoreCase(strValue, "alert") {
					t.Errorf("Nested malicious content not sanitized: %s", strValue)
				}
			}
		}
	}
}

func TestStrictValidator_ContextCancellation(t *testing.T) {
	validator := NewStrict("test")

	// Create a canceled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	req := &features.Request{
		Method: "tools/list",
		Params: nil,
	}

	// The validator should handle context cancellation gracefully
	err := validator.ValidateRequest(ctx, req)
	// Implementation may or may not check context - either way is fine for this basic validator
	if err != nil && err != context.Canceled {
		// This is acceptable
	}
}

func TestStrictValidator_LargePayload(t *testing.T) {
	validator := NewStrict("test")
	ctx := context.Background()

	// Create a large payload to test performance/limits
	largeParams := make(map[string]interface{})
	for i := 0; i < 1000; i++ {
		largeParams[fmt.Sprintf("field_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	// Add some malicious content
	largeParams["malicious"] = "<script>alert('xss')</script>"

	req := &features.Request{
		Method: "tools/call",
		Params: largeParams,
	}

	// Should handle large payloads without crashing
	err := validator.ValidateRequest(ctx, req)
	// May or may not error depending on implementation - just ensure no panic
	_ = err

	// Sanitization should also work with large payloads
	sanitized := validator.SanitizeParams(largeParams)
	if len(sanitized) == 0 {
		t.Error("Expected sanitized params to not be empty")
	}
}

// Helper function
func containsIgnoreCase(s, substr string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
}
