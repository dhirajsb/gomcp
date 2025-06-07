package security

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/dhirajsb/gomcp/telemetry"
	"go.opentelemetry.io/otel/trace"
)

// SecurityLevel represents the severity of a security issue
type SecurityLevel int

const (
	SecurityLevelInfo SecurityLevel = iota
	SecurityLevelLow
	SecurityLevelMedium
	SecurityLevelHigh
	SecurityLevelCritical
)

func (s SecurityLevel) String() string {
	switch s {
	case SecurityLevelInfo:
		return "INFO"
	case SecurityLevelLow:
		return "LOW"
	case SecurityLevelMedium:
		return "MEDIUM"
	case SecurityLevelHigh:
		return "HIGH"
	case SecurityLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// SecurityViolation represents a security validation violation
type SecurityViolation struct {
	Type       string        `json:"type"`
	Level      SecurityLevel `json:"level"`
	Message    string        `json:"message"`
	Field      string        `json:"field"`
	Value      string        `json:"value"`
	Rule       string        `json:"rule"`
	Suggestion string        `json:"suggestion"`
	References []string      `json:"references"`
}

// ValidationResult holds the result of security validation
type ValidationResult struct {
	Valid      bool                   `json:"valid"`
	Violations []SecurityViolation    `json:"violations"`
	Score      int                    `json:"score"`     // Security score (0-100)
	Sanitized  map[string]string      `json:"sanitized"` // Sanitized values
	Metadata   map[string]interface{} `json:"metadata"`
}

// SecurityValidator defines the interface for security validators
type SecurityValidator interface {
	// Validate validates input and returns violations
	Validate(ctx context.Context, input map[string]interface{}) (*ValidationResult, error)

	// ValidateString validates a single string value
	ValidateString(ctx context.Context, field, value string) (*ValidationResult, error)

	// Sanitize sanitizes input values
	Sanitize(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error)

	// SanitizeString sanitizes a single string value
	SanitizeString(ctx context.Context, value string) (string, error)

	// GetRules returns the validation rules
	GetRules() []ValidationRule

	// Type returns the validator type
	Type() string
}

// ValidationRule represents a validation rule
type ValidationRule struct {
	Name    string                 `json:"name"`
	Type    string                 `json:"type"`    // "regex", "blacklist", "whitelist", "length", "custom"
	Pattern string                 `json:"pattern"` // Regex pattern or rule definition
	Level   SecurityLevel          `json:"level"`
	Message string                 `json:"message"`
	Enabled bool                   `json:"enabled"`
	Fields  []string               `json:"fields"` // Applicable field names (* for all)
	Options map[string]interface{} `json:"options"`
}

// ValidatorConfig holds validator configuration
type ValidatorConfig struct {
	Enabled         bool                   `json:"enabled"`
	StrictMode      bool                   `json:"strict_mode"`    // Fail on any violation
	AutoSanitize    bool                   `json:"auto_sanitize"`  // Automatically sanitize input
	MaxViolations   int                    `json:"max_violations"` // Max violations before stopping
	Rules           []ValidationRule       `json:"rules"`
	CustomRules     []ValidationRule       `json:"custom_rules"`
	WhitelistFields []string               `json:"whitelist_fields"` // Fields to skip validation
	Config          map[string]interface{} `json:"config"`
}

// SecurityValidatorManager manages multiple security validators
type SecurityValidatorManager struct {
	validators map[string]SecurityValidator
	config     ValidatorConfig
	metrics    *SecurityMetrics
	tracer     trace.Tracer
}

// NewSecurityValidatorManager creates a new security validator manager
func NewSecurityValidatorManager(config ValidatorConfig) *SecurityValidatorManager {
	manager := &SecurityValidatorManager{
		validators: make(map[string]SecurityValidator),
		config:     config,
		metrics:    NewSecurityMetrics(),
	}

	// Register default validators if enabled
	if config.Enabled {
		manager.RegisterValidator(NewSQLInjectionValidator())
		manager.RegisterValidator(NewXSSValidator())
		manager.RegisterValidator(NewPathTraversalValidator())
		manager.RegisterValidator(NewCommandInjectionValidator())
		manager.RegisterValidator(NewInputValidationValidator())
	}

	return manager
}

// SetTracer sets the OpenTelemetry tracer for distributed tracing
func (m *SecurityValidatorManager) SetTracer(tracer trace.Tracer) {
	m.tracer = tracer
}

// RegisterValidator registers a security validator
func (m *SecurityValidatorManager) RegisterValidator(validator SecurityValidator) {
	m.validators[validator.Type()] = validator
}

// ValidateInput validates input using all registered validators
func (m *SecurityValidatorManager) ValidateInput(ctx context.Context, input map[string]interface{}) (*ValidationResult, error) {
	// Start distributed tracing span
	var span trace.Span
	if m.tracer != nil {
		ctx, span = telemetry.StartSpan(ctx, m.tracer, "security.validate_input",
			telemetry.NewSpanAttributeBuilder().
				Component("security").
				Operation("validate_input").
				Bool("security.enabled", m.config.Enabled).
				Bool("security.strict_mode", m.config.StrictMode).
				Bool("security.auto_sanitize", m.config.AutoSanitize).
				Int("security.max_violations", m.config.MaxViolations).
				Int("security.input_fields", len(input)).
				Build()...)
		defer span.End()
	}

	if !m.config.Enabled {
		if span != nil {
			telemetry.AddEvent(span, "security.validation.disabled")
			telemetry.RecordSuccess(span)
		}
		return &ValidationResult{Valid: true, Score: 100}, nil
	}

	result := &ValidationResult{
		Valid:      true,
		Violations: make([]SecurityViolation, 0),
		Score:      100,
		Sanitized:  make(map[string]string),
		Metadata:   make(map[string]interface{}),
	}

	// Skip whitelisted fields
	filteredInput := m.filterWhitelistedFields(input)
	filteredFieldCount := len(filteredInput)

	if span != nil {
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			Int("security.filtered_fields", filteredFieldCount).
			Int("security.whitelist_fields", len(m.config.WhitelistFields)).
			Build()...)
	}

	validatorsRun := 0
	violationsFound := 0
	sanitizationsPerformed := 0

	// Run all validators
	for validatorType, validator := range m.validators {
		validatorStart := time.Now()

		// Create child span for individual validator
		var validatorSpan trace.Span
		if span != nil {
			_, validatorSpan = telemetry.StartSpan(ctx, m.tracer, fmt.Sprintf("security.validator.%s", validatorType),
				telemetry.NewSpanAttributeBuilder().
					Component("security").
					Operation("validate").
					String("security.validator_type", validatorType).
					Build()...)
		}

		validationResult, err := validator.Validate(ctx, filteredInput)
		validatorLatency := time.Since(validatorStart)
		validatorsRun++

		if err != nil {
			m.metrics.RecordError(err)
			if validatorSpan != nil {
				telemetry.RecordError(validatorSpan, err)
				validatorSpan.End()
			}
			if span != nil {
				telemetry.RecordError(span, err)
			}
			return nil, fmt.Errorf("validator %s failed: %w", validatorType, err)
		}

		// Record metrics for this validator
		blocked := len(validationResult.Violations) > 0
		var threatLevel SecurityLevel = SecurityLevelLow
		if blocked && len(validationResult.Violations) > 0 {
			threatLevel = validationResult.Violations[0].Level
			violationsFound += len(validationResult.Violations)
		}
		m.metrics.RecordValidation(validatorType, blocked, validatorLatency, threatLevel)

		// Record validator span details
		if validatorSpan != nil {
			telemetry.SetSpanAttributes(validatorSpan, telemetry.NewSpanAttributeBuilder().
				Bool("security.blocked", blocked).
				Int("security.violations_count", len(validationResult.Violations)).
				Int("security.score", validationResult.Score).
				Security(threatLevel.String(), validatorType).
				Float64("security.latency_ms", float64(validatorLatency.Nanoseconds())/1000000.0).
				Build()...)

			if blocked {
				for _, violation := range validationResult.Violations {
					telemetry.AddEvent(validatorSpan, "security.violation.detected",
						telemetry.NewSpanAttributeBuilder().
							String("violation.type", violation.Type).
							String("violation.level", violation.Level.String()).
							String("violation.field", violation.Field).
							String("violation.rule", violation.Rule).
							String("violation.message", violation.Message).
							Build()...)
				}
			}
			telemetry.RecordSuccess(validatorSpan)
			validatorSpan.End()
		}

		// Record sanitizations
		if len(validationResult.Sanitized) > 0 {
			m.metrics.RecordSanitization(validatorType)
			sanitizationsPerformed += len(validationResult.Sanitized)
		}

		// Merge violations
		result.Violations = append(result.Violations, validationResult.Violations...)

		// Merge sanitized values
		for k, v := range validationResult.Sanitized {
			result.Sanitized[k] = v
		}

		// Update score (take minimum)
		if validationResult.Score < result.Score {
			result.Score = validationResult.Score
		}

		// Check max violations limit
		if m.config.MaxViolations > 0 && len(result.Violations) >= m.config.MaxViolations {
			if span != nil {
				telemetry.AddEvent(span, "security.validation.max_violations_reached")
			}
			break
		}
	}

	// Determine if valid
	result.Valid = len(result.Violations) == 0
	strictModeViolation := false
	if m.config.StrictMode {
		for _, violation := range result.Violations {
			if violation.Level >= SecurityLevelMedium {
				result.Valid = false
				strictModeViolation = true
				break
			}
		}
	}

	// Auto-sanitize if enabled
	autoSanitized := false
	if m.config.AutoSanitize && !result.Valid {
		sanitizedInput, err := m.SanitizeInput(ctx, input)
		if err != nil {
			if span != nil {
				telemetry.RecordError(span, err)
			}
			return result, err
		}

		// Convert sanitized input to string map
		for k, v := range sanitizedInput {
			if str, ok := v.(string); ok {
				result.Sanitized[k] = str
				autoSanitized = true
			}
		}
	}

	// Record final span attributes and events
	if span != nil {
		telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
			Bool("security.valid", result.Valid).
			Int("security.final_score", result.Score).
			Int("security.validators_run", validatorsRun).
			Int("security.total_violations", len(result.Violations)).
			Int("security.violations_found", violationsFound).
			Int("security.sanitizations_performed", sanitizationsPerformed).
			Bool("security.strict_mode_violation", strictModeViolation).
			Bool("security.auto_sanitized", autoSanitized).
			Build()...)

		if result.Valid {
			telemetry.AddEvent(span, "security.validation.passed")
		} else {
			telemetry.AddEvent(span, "security.validation.failed")
			// Add details about the most severe violation
			if len(result.Violations) > 0 {
				mostSevere := result.Violations[0]
				for _, v := range result.Violations {
					if v.Level > mostSevere.Level {
						mostSevere = v
					}
				}
				telemetry.SetSpanAttributes(span, telemetry.NewSpanAttributeBuilder().
					String("security.most_severe_violation_type", mostSevere.Type).
					String("security.most_severe_violation_level", mostSevere.Level.String()).
					String("security.most_severe_violation_field", mostSevere.Field).
					Build()...)
			}
		}
		telemetry.RecordSuccess(span)
	}

	return result, nil
}

// SanitizeInput sanitizes input using all registered validators
func (m *SecurityValidatorManager) SanitizeInput(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	if !m.config.Enabled {
		return input, nil
	}

	result := make(map[string]interface{})

	// Copy original input
	for k, v := range input {
		result[k] = v
	}

	// Apply sanitization from all validators
	for _, validator := range m.validators {
		sanitized, err := validator.Sanitize(ctx, result)
		if err != nil {
			return nil, err
		}

		// Update result with sanitized values
		for k, v := range sanitized {
			result[k] = v
		}
	}

	return result, nil
}

// filterWhitelistedFields removes whitelisted fields from input
func (m *SecurityValidatorManager) filterWhitelistedFields(input map[string]interface{}) map[string]interface{} {
	if len(m.config.WhitelistFields) == 0 {
		return input
	}

	result := make(map[string]interface{})
	whitelist := make(map[string]bool)

	for _, field := range m.config.WhitelistFields {
		whitelist[field] = true
	}

	for k, v := range input {
		if !whitelist[k] {
			result[k] = v
		}
	}

	return result
}

// SQL Injection Validator
type SQLInjectionValidator struct {
	rules []ValidationRule
}

func NewSQLInjectionValidator() *SQLInjectionValidator {
	rules := []ValidationRule{
		{
			Name:    "sql_keywords",
			Type:    "regex",
			Pattern: `(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION|OR|AND)\b`,
			Level:   SecurityLevelHigh,
			Message: "Potential SQL injection detected: SQL keywords found",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "sql_comments",
			Type:    "regex",
			Pattern: `(/\*[\s\S]*?\*/|--[^\r\n]*|#[^\r\n]*)`,
			Level:   SecurityLevelMedium,
			Message: "Potential SQL injection detected: SQL comments found",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "sql_quotes",
			Type:    "regex",
			Pattern: `(['"][\s]*;[\s]*['"]|['"][\s]*\||['"][\s]*#)`,
			Level:   SecurityLevelHigh,
			Message: "Potential SQL injection detected: malicious quote patterns",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "sql_functions",
			Type:    "regex",
			Pattern: `(?i)\b(CONCAT|SUBSTRING|ASCII|CHAR|SLEEP|BENCHMARK|LOAD_FILE|INTO OUTFILE)\b`,
			Level:   SecurityLevelMedium,
			Message: "Potential SQL injection detected: dangerous SQL functions",
			Enabled: true,
			Fields:  []string{"*"},
		},
	}

	return &SQLInjectionValidator{rules: rules}
}

func (v *SQLInjectionValidator) Validate(ctx context.Context, input map[string]interface{}) (*ValidationResult, error) {
	return v.validateWithRules(input, v.rules)
}

func (v *SQLInjectionValidator) ValidateString(ctx context.Context, field, value string) (*ValidationResult, error) {
	input := map[string]interface{}{field: value}
	return v.validateWithRules(input, v.rules)
}

func (v *SQLInjectionValidator) validateWithRules(input map[string]interface{}, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:      true,
		Violations: make([]SecurityViolation, 0),
		Score:      100,
		Sanitized:  make(map[string]string),
	}

	for field, value := range input {
		str, ok := value.(string)
		if !ok {
			continue
		}

		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}

			if !v.ruleAppliesTo(rule, field) {
				continue
			}

			if matched, _ := regexp.MatchString(rule.Pattern, str); matched {
				violation := SecurityViolation{
					Type:       "sql_injection",
					Level:      rule.Level,
					Message:    rule.Message,
					Field:      field,
					Value:      str,
					Rule:       rule.Name,
					Suggestion: "Remove or escape SQL keywords and special characters",
					References: []string{
						"https://owasp.org/www-community/attacks/SQL_Injection",
						"https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
					},
				}

				result.Violations = append(result.Violations, violation)
				result.Valid = false

				// Reduce score based on severity
				switch rule.Level {
				case SecurityLevelHigh, SecurityLevelCritical:
					result.Score -= 30
				case SecurityLevelMedium:
					result.Score -= 20
				case SecurityLevelLow:
					result.Score -= 10
				}
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result, nil
}

func (v *SQLInjectionValidator) Sanitize(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for k, value := range input {
		if str, ok := value.(string); ok {
			sanitized := v.sanitizeSQL(str)
			result[k] = sanitized
		} else {
			result[k] = value
		}
	}

	return result, nil
}

func (v *SQLInjectionValidator) SanitizeString(ctx context.Context, value string) (string, error) {
	return v.sanitizeSQL(value), nil
}

func (v *SQLInjectionValidator) sanitizeSQL(input string) string {
	// Remove SQL comments
	re1 := regexp.MustCompile(`(/\*[\s\S]*?\*/|--[^\r\n]*|#[^\r\n]*)`)
	sanitized := re1.ReplaceAllString(input, "")

	// Escape single quotes
	sanitized = strings.ReplaceAll(sanitized, "'", "''")

	// Remove or escape dangerous patterns
	re2 := regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE|UNION)\b`)
	sanitized = re2.ReplaceAllStringFunc(sanitized, func(match string) string {
		return strings.ReplaceAll(match, match, "["+match+"]")
	})

	return sanitized
}

func (v *SQLInjectionValidator) ruleAppliesTo(rule ValidationRule, field string) bool {
	if len(rule.Fields) == 0 {
		return true
	}

	for _, ruleField := range rule.Fields {
		if ruleField == "*" || ruleField == field {
			return true
		}
	}

	return false
}

func (v *SQLInjectionValidator) GetRules() []ValidationRule {
	return v.rules
}

func (v *SQLInjectionValidator) Type() string {
	return "sql_injection"
}

// XSS Validator
type XSSValidator struct {
	rules []ValidationRule
}

func NewXSSValidator() *XSSValidator {
	rules := []ValidationRule{
		{
			Name:    "script_tags",
			Type:    "regex",
			Pattern: `(?i)<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>`,
			Level:   SecurityLevelCritical,
			Message: "XSS detected: script tags found",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "event_handlers",
			Type:    "regex",
			Pattern: `(?i)\bon\w+\s*=`,
			Level:   SecurityLevelHigh,
			Message: "XSS detected: JavaScript event handlers found",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "javascript_protocol",
			Type:    "regex",
			Pattern: `(?i)javascript\s*:`,
			Level:   SecurityLevelHigh,
			Message: "XSS detected: javascript protocol found",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "dangerous_tags",
			Type:    "regex",
			Pattern: `(?i)<\s*(iframe|object|embed|form|input|textarea|button)[^>]*>`,
			Level:   SecurityLevelMedium,
			Message: "XSS detected: potentially dangerous HTML tags",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "data_urls",
			Type:    "regex",
			Pattern: `(?i)data\s*:\s*[^;]*;base64`,
			Level:   SecurityLevelMedium,
			Message: "XSS detected: base64 data URLs found",
			Enabled: true,
			Fields:  []string{"*"},
		},
	}

	return &XSSValidator{rules: rules}
}

func (v *XSSValidator) Validate(ctx context.Context, input map[string]interface{}) (*ValidationResult, error) {
	return v.validateWithRules(input, v.rules)
}

func (v *XSSValidator) ValidateString(ctx context.Context, field, value string) (*ValidationResult, error) {
	input := map[string]interface{}{field: value}
	return v.validateWithRules(input, v.rules)
}

func (v *XSSValidator) validateWithRules(input map[string]interface{}, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:      true,
		Violations: make([]SecurityViolation, 0),
		Score:      100,
		Sanitized:  make(map[string]string),
	}

	for field, value := range input {
		str, ok := value.(string)
		if !ok {
			continue
		}

		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}

			if matched, _ := regexp.MatchString(rule.Pattern, str); matched {
				violation := SecurityViolation{
					Type:       "xss",
					Level:      rule.Level,
					Message:    rule.Message,
					Field:      field,
					Value:      str,
					Rule:       rule.Name,
					Suggestion: "Remove or properly escape HTML/JavaScript content",
					References: []string{
						"https://owasp.org/www-community/attacks/xss/",
						"https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
					},
				}

				result.Violations = append(result.Violations, violation)
				result.Valid = false

				// Reduce score based on severity
				switch rule.Level {
				case SecurityLevelCritical:
					result.Score -= 40
				case SecurityLevelHigh:
					result.Score -= 30
				case SecurityLevelMedium:
					result.Score -= 20
				case SecurityLevelLow:
					result.Score -= 10
				}
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result, nil
}

func (v *XSSValidator) Sanitize(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for k, value := range input {
		if str, ok := value.(string); ok {
			sanitized := v.sanitizeHTML(str)
			result[k] = sanitized
		} else {
			result[k] = value
		}
	}

	return result, nil
}

func (v *XSSValidator) SanitizeString(ctx context.Context, value string) (string, error) {
	return v.sanitizeHTML(value), nil
}

func (v *XSSValidator) sanitizeHTML(input string) string {
	// Remove script tags
	re1 := regexp.MustCompile(`(?i)<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>`)
	sanitized := re1.ReplaceAllString(input, "")

	// Remove event handlers
	re2 := regexp.MustCompile(`(?i)\s*on\w+\s*=\s*['"]\s*[^'"]*\s*['"]`)
	sanitized = re2.ReplaceAllString(sanitized, "")

	// Remove javascript: protocol
	re3 := regexp.MustCompile(`(?i)javascript\s*:`)
	sanitized = re3.ReplaceAllString(sanitized, "")

	// Escape HTML entities
	sanitized = strings.ReplaceAll(sanitized, "<", "&lt;")
	sanitized = strings.ReplaceAll(sanitized, ">", "&gt;")
	sanitized = strings.ReplaceAll(sanitized, "\"", "&quot;")
	sanitized = strings.ReplaceAll(sanitized, "'", "&#x27;")

	return sanitized
}

func (v *XSSValidator) GetRules() []ValidationRule {
	return v.rules
}

func (v *XSSValidator) Type() string {
	return "xss"
}

// Path Traversal Validator
type PathTraversalValidator struct {
	rules []ValidationRule
}

func NewPathTraversalValidator() *PathTraversalValidator {
	rules := []ValidationRule{
		{
			Name:    "dot_dot_slash",
			Type:    "regex",
			Pattern: `\.\.[\\/]`,
			Level:   SecurityLevelHigh,
			Message: "Path traversal detected: directory traversal patterns",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "absolute_paths",
			Type:    "regex",
			Pattern: `^[\\/]|^[a-zA-Z]:[\\]`,
			Level:   SecurityLevelMedium,
			Message: "Path traversal detected: absolute path usage",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "url_encoded_traversal",
			Type:    "regex",
			Pattern: `%2e%2e[\\/]|%2e%2e%2f|%2e%2e%5c`,
			Level:   SecurityLevelHigh,
			Message: "Path traversal detected: URL-encoded traversal patterns",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "null_bytes",
			Type:    "regex",
			Pattern: `\x00|%00`,
			Level:   SecurityLevelCritical,
			Message: "Path traversal detected: null byte injection",
			Enabled: true,
			Fields:  []string{"*"},
		},
	}

	return &PathTraversalValidator{rules: rules}
}

func (v *PathTraversalValidator) Validate(ctx context.Context, input map[string]interface{}) (*ValidationResult, error) {
	return v.validateWithRules(input, v.rules)
}

func (v *PathTraversalValidator) ValidateString(ctx context.Context, field, value string) (*ValidationResult, error) {
	input := map[string]interface{}{field: value}
	return v.validateWithRules(input, v.rules)
}

func (v *PathTraversalValidator) validateWithRules(input map[string]interface{}, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:      true,
		Violations: make([]SecurityViolation, 0),
		Score:      100,
		Sanitized:  make(map[string]string),
	}

	for field, value := range input {
		str, ok := value.(string)
		if !ok {
			continue
		}

		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}

			if matched, _ := regexp.MatchString(rule.Pattern, str); matched {
				violation := SecurityViolation{
					Type:       "path_traversal",
					Level:      rule.Level,
					Message:    rule.Message,
					Field:      field,
					Value:      str,
					Rule:       rule.Name,
					Suggestion: "Use relative paths and validate against allowed directories",
					References: []string{
						"https://owasp.org/www-community/attacks/Path_Traversal",
						"https://cwe.mitre.org/data/definitions/22.html",
					},
				}

				result.Violations = append(result.Violations, violation)
				result.Valid = false

				// Reduce score based on severity
				switch rule.Level {
				case SecurityLevelCritical:
					result.Score -= 40
				case SecurityLevelHigh:
					result.Score -= 30
				case SecurityLevelMedium:
					result.Score -= 20
				case SecurityLevelLow:
					result.Score -= 10
				}
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result, nil
}

func (v *PathTraversalValidator) Sanitize(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for k, value := range input {
		if str, ok := value.(string); ok {
			sanitized := v.sanitizePath(str)
			result[k] = sanitized
		} else {
			result[k] = value
		}
	}

	return result, nil
}

func (v *PathTraversalValidator) SanitizeString(ctx context.Context, value string) (string, error) {
	return v.sanitizePath(value), nil
}

func (v *PathTraversalValidator) sanitizePath(input string) string {
	// Remove null bytes
	sanitized := strings.ReplaceAll(input, "\x00", "")
	sanitized = strings.ReplaceAll(sanitized, "%00", "")

	// Remove directory traversal patterns
	re1 := regexp.MustCompile(`\.\.[\\/]+`)
	sanitized = re1.ReplaceAllString(sanitized, "")

	// URL decode common patterns
	sanitized = strings.ReplaceAll(sanitized, "%2e", ".")
	sanitized = strings.ReplaceAll(sanitized, "%2f", "/")
	sanitized = strings.ReplaceAll(sanitized, "%5c", "\\")

	// Clean and normalize path
	if cleaned := filepath.Clean(sanitized); cleaned != "." {
		sanitized = cleaned
	}

	return sanitized
}

func (v *PathTraversalValidator) GetRules() []ValidationRule {
	return v.rules
}

func (v *PathTraversalValidator) Type() string {
	return "path_traversal"
}

// Command Injection Validator
type CommandInjectionValidator struct {
	rules []ValidationRule
}

func NewCommandInjectionValidator() *CommandInjectionValidator {
	rules := []ValidationRule{
		{
			Name:    "command_separators",
			Type:    "regex",
			Pattern: `[;&|` + "`" + `$()]`,
			Level:   SecurityLevelHigh,
			Message: "Command injection detected: command separator characters",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "shell_commands",
			Type:    "regex",
			Pattern: `(?i)\b(cat|ls|dir|type|echo|ping|wget|curl|rm|del|mv|cp|chmod|chown|sudo|su|passwd|kill|ps|netstat|ifconfig|whoami)\b`,
			Level:   SecurityLevelMedium,
			Message: "Command injection detected: shell command keywords",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "redirections",
			Type:    "regex",
			Pattern: `[<>]+|2>&1|\|\s*tee`,
			Level:   SecurityLevelHigh,
			Message: "Command injection detected: I/O redirection operators",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "environment_vars",
			Type:    "regex",
			Pattern: `\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`,
			Level:   SecurityLevelMedium,
			Message: "Command injection detected: environment variable expansion",
			Enabled: true,
			Fields:  []string{"*"},
		},
	}

	return &CommandInjectionValidator{rules: rules}
}

func (v *CommandInjectionValidator) Validate(ctx context.Context, input map[string]interface{}) (*ValidationResult, error) {
	return v.validateWithRules(input, v.rules)
}

func (v *CommandInjectionValidator) ValidateString(ctx context.Context, field, value string) (*ValidationResult, error) {
	input := map[string]interface{}{field: value}
	return v.validateWithRules(input, v.rules)
}

func (v *CommandInjectionValidator) validateWithRules(input map[string]interface{}, rules []ValidationRule) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:      true,
		Violations: make([]SecurityViolation, 0),
		Score:      100,
		Sanitized:  make(map[string]string),
	}

	for field, value := range input {
		str, ok := value.(string)
		if !ok {
			continue
		}

		for _, rule := range rules {
			if !rule.Enabled {
				continue
			}

			if matched, _ := regexp.MatchString(rule.Pattern, str); matched {
				violation := SecurityViolation{
					Type:       "command_injection",
					Level:      rule.Level,
					Message:    rule.Message,
					Field:      field,
					Value:      str,
					Rule:       rule.Name,
					Suggestion: "Remove or escape shell metacharacters and validate input",
					References: []string{
						"https://owasp.org/www-community/attacks/Command_Injection",
						"https://cwe.mitre.org/data/definitions/78.html",
					},
				}

				result.Violations = append(result.Violations, violation)
				result.Valid = false

				// Reduce score based on severity
				switch rule.Level {
				case SecurityLevelCritical:
					result.Score -= 40
				case SecurityLevelHigh:
					result.Score -= 30
				case SecurityLevelMedium:
					result.Score -= 20
				case SecurityLevelLow:
					result.Score -= 10
				}
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result, nil
}

func (v *CommandInjectionValidator) Sanitize(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for k, value := range input {
		if str, ok := value.(string); ok {
			sanitized := v.sanitizeCommand(str)
			result[k] = sanitized
		} else {
			result[k] = value
		}
	}

	return result, nil
}

func (v *CommandInjectionValidator) SanitizeString(ctx context.Context, value string) (string, error) {
	return v.sanitizeCommand(value), nil
}

func (v *CommandInjectionValidator) sanitizeCommand(input string) string {
	// Remove dangerous characters
	dangerous := []string{";", "&", "|", "`", "$", "(", ")", "<", ">", "\\"}
	sanitized := input

	for _, char := range dangerous {
		sanitized = strings.ReplaceAll(sanitized, char, "")
	}

	// Remove environment variable patterns
	re := regexp.MustCompile(`\$\{[^}]*\}|\$[A-Za-z_][A-Za-z0-9_]*`)
	sanitized = re.ReplaceAllString(sanitized, "")

	return sanitized
}

func (v *CommandInjectionValidator) GetRules() []ValidationRule {
	return v.rules
}

func (v *CommandInjectionValidator) Type() string {
	return "command_injection"
}

// Input Validation Validator (general input validation)
type InputValidationValidator struct {
	rules []ValidationRule
}

func NewInputValidationValidator() *InputValidationValidator {
	rules := []ValidationRule{
		{
			Name:    "excessive_length",
			Type:    "length",
			Pattern: "10000", // Max length
			Level:   SecurityLevelMedium,
			Message: "Input validation: excessive input length",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "control_characters",
			Type:    "regex",
			Pattern: `[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]`,
			Level:   SecurityLevelLow,
			Message: "Input validation: control characters detected",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "unicode_exploits",
			Type:    "regex",
			Pattern: `[\uFEFF\u200B-\u200F\u202A-\u202E\u2060-\u206F]`,
			Level:   SecurityLevelMedium,
			Message: "Input validation: potentially malicious Unicode characters",
			Enabled: true,
			Fields:  []string{"*"},
		},
		{
			Name:    "url_validation",
			Type:    "custom",
			Pattern: "url",
			Level:   SecurityLevelMedium,
			Message: "Input validation: invalid URL format",
			Enabled: true,
			Fields:  []string{"url", "link", "href", "src"},
		},
		{
			Name:    "email_validation",
			Type:    "custom",
			Pattern: "email",
			Level:   SecurityLevelLow,
			Message: "Input validation: invalid email format",
			Enabled: true,
			Fields:  []string{"email", "mail"},
		},
		{
			Name:    "ip_validation",
			Type:    "custom",
			Pattern: "ip",
			Level:   SecurityLevelMedium,
			Message: "Input validation: invalid IP address format",
			Enabled: true,
			Fields:  []string{"ip", "address", "host"},
		},
	}

	return &InputValidationValidator{rules: rules}
}

func (v *InputValidationValidator) Validate(ctx context.Context, input map[string]interface{}) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:      true,
		Violations: make([]SecurityViolation, 0),
		Score:      100,
		Sanitized:  make(map[string]string),
	}

	for field, value := range input {
		str, ok := value.(string)
		if !ok {
			continue
		}

		for _, rule := range v.rules {
			if !rule.Enabled {
				continue
			}

			if !v.ruleAppliesTo(rule, field) {
				continue
			}

			violation := v.validateRule(rule, field, str)
			if violation != nil {
				result.Violations = append(result.Violations, *violation)
				result.Valid = false

				// Reduce score based on severity
				switch rule.Level {
				case SecurityLevelCritical:
					result.Score -= 40
				case SecurityLevelHigh:
					result.Score -= 30
				case SecurityLevelMedium:
					result.Score -= 20
				case SecurityLevelLow:
					result.Score -= 10
				}
			}
		}
	}

	if result.Score < 0 {
		result.Score = 0
	}

	return result, nil
}

func (v *InputValidationValidator) validateRule(rule ValidationRule, field, value string) *SecurityViolation {
	switch rule.Type {
	case "regex":
		if matched, _ := regexp.MatchString(rule.Pattern, value); matched {
			return &SecurityViolation{
				Type:       "input_validation",
				Level:      rule.Level,
				Message:    rule.Message,
				Field:      field,
				Value:      value,
				Rule:       rule.Name,
				Suggestion: "Ensure input follows expected format and encoding",
			}
		}
	case "length":
		if maxLen, err := strconv.Atoi(rule.Pattern); err == nil && len(value) > maxLen {
			return &SecurityViolation{
				Type:       "input_validation",
				Level:      rule.Level,
				Message:    rule.Message,
				Field:      field,
				Value:      fmt.Sprintf("%d characters", len(value)),
				Rule:       rule.Name,
				Suggestion: fmt.Sprintf("Limit input to maximum %d characters", maxLen),
			}
		}
	case "custom":
		return v.validateCustomRule(rule, field, value)
	}

	return nil
}

func (v *InputValidationValidator) validateCustomRule(rule ValidationRule, field, value string) *SecurityViolation {
	switch rule.Pattern {
	case "url":
		if _, err := url.ParseRequestURI(value); err != nil {
			return &SecurityViolation{
				Type:       "input_validation",
				Level:      rule.Level,
				Message:    rule.Message,
				Field:      field,
				Value:      value,
				Rule:       rule.Name,
				Suggestion: "Provide a valid URL format",
			}
		}
	case "email":
		emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
		if !emailRegex.MatchString(value) {
			return &SecurityViolation{
				Type:       "input_validation",
				Level:      rule.Level,
				Message:    rule.Message,
				Field:      field,
				Value:      value,
				Rule:       rule.Name,
				Suggestion: "Provide a valid email address format",
			}
		}
	case "ip":
		if net.ParseIP(value) == nil {
			return &SecurityViolation{
				Type:       "input_validation",
				Level:      rule.Level,
				Message:    rule.Message,
				Field:      field,
				Value:      value,
				Rule:       rule.Name,
				Suggestion: "Provide a valid IP address format",
			}
		}
	}

	return nil
}

func (v *InputValidationValidator) ValidateString(ctx context.Context, field, value string) (*ValidationResult, error) {
	input := map[string]interface{}{field: value}
	return v.Validate(ctx, input)
}

func (v *InputValidationValidator) Sanitize(ctx context.Context, input map[string]interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	for k, value := range input {
		if str, ok := value.(string); ok {
			sanitized := v.sanitizeInput(str)
			result[k] = sanitized
		} else {
			result[k] = value
		}
	}

	return result, nil
}

func (v *InputValidationValidator) SanitizeString(ctx context.Context, value string) (string, error) {
	return v.sanitizeInput(value), nil
}

func (v *InputValidationValidator) sanitizeInput(input string) string {
	// Remove control characters
	var result strings.Builder
	for _, r := range input {
		if !unicode.IsControl(r) || r == '\n' || r == '\r' || r == '\t' {
			result.WriteRune(r)
		}
	}

	sanitized := result.String()

	// Limit length
	if len(sanitized) > 10000 {
		sanitized = sanitized[:10000]
	}

	return sanitized
}

func (v *InputValidationValidator) ruleAppliesTo(rule ValidationRule, field string) bool {
	if len(rule.Fields) == 0 {
		return true
	}

	for _, ruleField := range rule.Fields {
		if ruleField == "*" || strings.Contains(strings.ToLower(field), strings.ToLower(ruleField)) {
			return true
		}
	}

	return false
}

func (v *InputValidationValidator) GetRules() []ValidationRule {
	return v.rules
}

func (v *InputValidationValidator) Type() string {
	return "input_validation"
}

// GetMetrics returns security metrics
func (m *SecurityValidatorManager) GetMetrics() map[string]interface{} {
	return m.metrics.GetStats()
}

// GetValidatorMetrics returns detailed validator metrics
func (m *SecurityValidatorManager) GetValidatorMetrics() map[string]*ValidatorMetrics {
	return m.metrics.GetValidatorStats()
}
