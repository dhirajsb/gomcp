package security

import (
	"context"
	"fmt"
	"html"
	"regexp"
	"strings"

	"github.com/dhirajsb/gomcp/internal/types"
	"github.com/microcosm-cc/bluemonday"
)

// StrictValidator implements strict security validation
type StrictValidator struct {
	name            string
	htmlSanitizer   *bluemonday.Policy
	validMethods    map[string]bool
	sqlPatterns     []*regexp.Regexp
	xssPatterns     []*regexp.Regexp
	pathPatterns    []*regexp.Regexp
	commandPatterns []*regexp.Regexp
}

// NewStrict creates a new strict validator
func NewStrict(name string) *StrictValidator {
	validator := &StrictValidator{
		name:          name,
		htmlSanitizer: bluemonday.StrictPolicy(),
		validMethods: map[string]bool{
			"tools/list":     true,
			"tools/call":     true,
			"resources/list": true,
			"resources/read": true,
			"prompts/list":   true,
			"prompts/get":    true,
			"ping":           true,
			"initialize":     true,
		},
	}

	// Compile security patterns
	validator.compilePatterns()
	return validator
}

// compilePatterns compiles all security detection patterns
func (sv *StrictValidator) compilePatterns() {
	// SQL injection patterns
	sqlPatterns := []string{
		`(?i)(union|select|insert|update|delete|drop|create|alter|exec|execute)\s`,
		`(?i)(or|and)\s+\d+\s*=\s*\d+`,
		`(?i)'(\s)*(or|and)`,
		`--`,
		`;.*\w`,
		`\bxp_\w+`,
		`\bsp_\w+`,
		`(?i)drop\s+table`,
		`(?i)union\s+select`,
		`(?i)information_schema`,
	}

	// XSS patterns
	xssPatterns := []string{
		`(?i)<script[^>]*>.*?</script>`,
		`(?i)<iframe[^>]*>.*?</iframe>`,
		`(?i)javascript:`,
		`(?i)on(load|error|click|mouse)=`,
		`(?i)<img[^>]*onerror`,
		`(?i)alert\s*\(`,
		`(?i)document\.cookie`,
		`(?i)eval\s*\(`,
	}

	// Path traversal patterns
	pathPatterns := []string{
		`\.\.\/`,
		`\.\.\\`,
		`\/etc\/passwd`,
		`\/proc\/`,
		`\.\..*\/`,
		`%2e%2e`,
		`\.\.%2f`,
	}

	// Command injection patterns
	commandPatterns := []string{
		`(?i)rm\s+-rf`,
		`(?i)(cat|ls|pwd|whoami|id)\s`,
		`(?i)(curl|wget|nc|netcat)\s`,
		`[\|&;<>]`,
		`\$\(.*\)`,
		"`.*`",
		`(?i)(sudo|su)\s`,
	}

	// Compile patterns
	sv.sqlPatterns = compileRegexList(sqlPatterns)
	sv.xssPatterns = compileRegexList(xssPatterns)
	sv.pathPatterns = compileRegexList(pathPatterns)
	sv.commandPatterns = compileRegexList(commandPatterns)
}

// compileRegexList compiles a list of regex patterns
func compileRegexList(patterns []string) []*regexp.Regexp {
	var compiled []*regexp.Regexp
	for _, pattern := range patterns {
		if re, err := regexp.Compile(pattern); err == nil {
			compiled = append(compiled, re)
		}
	}
	return compiled
}

func (sv *StrictValidator) Name() string {
	return sv.name
}

func (sv *StrictValidator) ValidateRequest(ctx context.Context, req *types.Request) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.Method == "" {
		return fmt.Errorf("method required")
	}

	// Validate method name
	if err := sv.validateMethod(req.Method); err != nil {
		return err
	}

	// Validate parameters if present
	if req.Params != nil {
		if err := sv.validateParams(req.Params); err != nil {
			return err
		}
	}

	return nil
}

// validateMethod validates the method name for security issues
func (sv *StrictValidator) validateMethod(method string) error {
	// Check if method contains invalid characters
	if strings.ContainsAny(method, " \t\n\r") {
		return fmt.Errorf("method contains invalid characters")
	}

	// Check for dangerous patterns in method name
	if sv.containsDangerousPatterns(method) {
		return fmt.Errorf("method contains dangerous patterns")
	}

	// For strict validation, only allow known methods
	if !sv.validMethods[method] {
		return fmt.Errorf("method not allowed: %s", method)
	}

	return nil
}

// validateParams validates request parameters for security issues
func (sv *StrictValidator) validateParams(params interface{}) error {
	return sv.validateValue(params)
}

// validateValue recursively validates any value for security issues
func (sv *StrictValidator) validateValue(value interface{}) error {
	switch v := value.(type) {
	case string:
		if sv.containsDangerousPatterns(v) {
			return fmt.Errorf("parameter contains dangerous patterns")
		}
	case map[string]interface{}:
		for _, val := range v {
			if err := sv.validateValue(val); err != nil {
				return err
			}
		}
	case []interface{}:
		for _, val := range v {
			if err := sv.validateValue(val); err != nil {
				return err
			}
		}
	}
	return nil
}

// containsDangerousPatterns checks if a string contains dangerous security patterns
func (sv *StrictValidator) containsDangerousPatterns(s string) bool {
	// Check SQL injection patterns
	for _, pattern := range sv.sqlPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	// Check XSS patterns
	for _, pattern := range sv.xssPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	// Check path traversal patterns
	for _, pattern := range sv.pathPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	// Check command injection patterns
	for _, pattern := range sv.commandPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}

	return false
}

func (sv *StrictValidator) SanitizeParams(params map[string]interface{}) map[string]interface{} {
	if params == nil {
		return make(map[string]interface{})
	}

	sanitized := make(map[string]interface{})
	for key, value := range params {
		sanitized[key] = sv.sanitizeValue(value)
	}

	return sanitized
}

// sanitizeValue recursively sanitizes any value
func (sv *StrictValidator) sanitizeValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return sv.sanitizeString(v)
	case map[string]interface{}:
		sanitized := make(map[string]interface{})
		for key, val := range v {
			sanitized[key] = sv.sanitizeValue(val)
		}
		return sanitized
	case []interface{}:
		sanitized := make([]interface{}, len(v))
		for i, val := range v {
			sanitized[i] = sv.sanitizeValue(val)
		}
		return sanitized
	default:
		// Non-string values are returned as-is
		return value
	}
}

// sanitizeString sanitizes a string by removing dangerous patterns
func (sv *StrictValidator) sanitizeString(s string) string {
	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")

	// Sanitize HTML/XSS
	s = sv.htmlSanitizer.Sanitize(s)

	// Additional HTML escaping
	s = html.EscapeString(s)

	// Remove SQL injection patterns
	s = sv.removeSQLPatterns(s)

	// Remove path traversal patterns
	s = sv.removePathTraversalPatterns(s)

	// Remove command injection patterns
	s = sv.removeCommandInjectionPatterns(s)

	return s
}

// removeSQLPatterns removes SQL injection patterns
func (sv *StrictValidator) removeSQLPatterns(s string) string {
	// Remove common SQL keywords and patterns
	dangerousSQL := []string{
		"DROP TABLE", "drop table",
		"DELETE FROM", "delete from",
		"INSERT INTO", "insert into",
		"UPDATE SET", "update set",
		"UNION SELECT", "union select",
		"';", `";`,
		"--",
		"/*", "*/",
	}

	for _, pattern := range dangerousSQL {
		s = strings.ReplaceAll(s, pattern, "")
	}

	return s
}

// removePathTraversalPatterns removes path traversal patterns
func (sv *StrictValidator) removePathTraversalPatterns(s string) string {
	pathPatterns := []string{
		"../", "..\\",
		"%2e%2e/", "%2e%2e\\",
		"..%2f", "..%5c",
	}

	for _, pattern := range pathPatterns {
		s = strings.ReplaceAll(s, pattern, "")
	}

	return s
}

// removeCommandInjectionPatterns removes command injection patterns
func (sv *StrictValidator) removeCommandInjectionPatterns(s string) string {
	commandPatterns := []string{
		"rm -rf", "RM -RF",
		"|", "&", ";",
		"$(", ")",
		"`",
	}

	for _, pattern := range commandPatterns {
		s = strings.ReplaceAll(s, pattern, "")
	}

	return s
}
