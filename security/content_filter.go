package security

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
)

// ContentFilter implements request filtering and content scanning
type ContentFilter struct {
	config ContentFilterConfig
	rules  []ContentFilterRule
	mu     sync.RWMutex
}

// ContentFilterConfig holds content filter configuration
type ContentFilterConfig struct {
	Enabled           bool                   `json:"enabled"`
	MaxRequestSize    int64                  `json:"max_request_size"`
	MaxResponseSize   int64                  `json:"max_response_size"`
	ScanBinaryContent bool                   `json:"scan_binary_content"`
	StrictMode        bool                   `json:"strict_mode"`
	Rules             []ContentFilterRule    `json:"rules"`
	Config            map[string]interface{} `json:"config"`
}

// ContentFilterRule represents a content filtering rule
type ContentFilterRule struct {
	Name        string                 `json:"name"`
	Type        string                 `json:"type"` // "regex", "keyword", "mime_type", "file_extension"
	Pattern     string                 `json:"pattern"`
	Action      string                 `json:"action"` // "block", "sanitize", "warn", "log"
	Level       SecurityLevel          `json:"level"`
	Enabled     bool                   `json:"enabled"`
	Description string                 `json:"description"`
	Categories  []string               `json:"categories"` // "malware", "spam", "adult", "violence", etc.
	Options     map[string]interface{} `json:"options"`
}

// ContentFilterResult holds the result of content filtering
type ContentFilterResult struct {
	Allowed      bool                   `json:"allowed"`
	Action       string                 `json:"action"`
	Violations   []ContentViolation     `json:"violations"`
	Sanitized    bool                   `json:"sanitized"`
	OriginalSize int64                  `json:"original_size"`
	FilteredSize int64                  `json:"filtered_size"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ContentViolation represents a content filtering violation
type ContentViolation struct {
	Rule       string        `json:"rule"`
	Type       string        `json:"type"`
	Level      SecurityLevel `json:"level"`
	Message    string        `json:"message"`
	Location   string        `json:"location"` // "header", "body", "url", "parameter"
	Field      string        `json:"field"`
	Value      string        `json:"value"`
	Category   string        `json:"category"`
	Action     string        `json:"action"`
	Suggestion string        `json:"suggestion"`
}

// NewContentFilter creates a new content filter
func NewContentFilter(config ContentFilterConfig) *ContentFilter {
	filter := &ContentFilter{
		config: config,
		rules:  make([]ContentFilterRule, 0),
	}

	// Add default rules
	filter.addDefaultRules()

	// Add custom rules from config
	filter.rules = append(filter.rules, config.Rules...)

	return filter
}

// addDefaultRules adds default content filtering rules
func (cf *ContentFilter) addDefaultRules() {
	defaultRules := []ContentFilterRule{
		{
			Name:        "malware_signatures",
			Type:        "regex",
			Pattern:     `(?i)(eicar|malware|virus|trojan|backdoor|rootkit|keylogger|ransomware)`,
			Action:      "block",
			Level:       SecurityLevelCritical,
			Enabled:     true,
			Description: "Detects common malware signatures and keywords",
			Categories:  []string{"malware", "security"},
		},
		{
			Name:        "suspicious_file_extensions",
			Type:        "file_extension",
			Pattern:     `(?i)\.(exe|scr|pif|com|bat|cmd|vbs|js|jar|app|dmg|pkg|deb|rpm)$`,
			Action:      "block",
			Level:       SecurityLevelHigh,
			Enabled:     true,
			Description: "Blocks potentially dangerous file extensions",
			Categories:  []string{"malware", "executable"},
		},
		{
			Name:        "suspicious_mime_types",
			Type:        "mime_type",
			Pattern:     `^application/(x-msdownload|x-msdos-program|x-executable|x-winexe|octet-stream)`,
			Action:      "warn",
			Level:       SecurityLevelMedium,
			Enabled:     true,
			Description: "Warns about suspicious MIME types",
			Categories:  []string{"executable", "binary"},
		},
		{
			Name:        "spam_keywords",
			Type:        "keyword",
			Pattern:     `(?i)\b(viagra|cialis|casino|lottery|winner|congratulations|claim.*prize|urgent.*action|act.*now)\b`,
			Action:      "warn",
			Level:       SecurityLevelLow,
			Enabled:     true,
			Description: "Detects common spam keywords",
			Categories:  []string{"spam", "marketing"},
		},
		{
			Name:        "profanity_filter",
			Type:        "regex",
			Pattern:     `(?i)\b(fuck|shit|damn|bitch|asshole|bastard|crap)\b`,
			Action:      "sanitize",
			Level:       SecurityLevelLow,
			Enabled:     false, // Disabled by default
			Description: "Filters profanity and offensive language",
			Categories:  []string{"profanity", "content"},
		},
		{
			Name:        "personal_info_ssn",
			Type:        "regex",
			Pattern:     `\b\d{3}-?\d{2}-?\d{4}\b`,
			Action:      "sanitize",
			Level:       SecurityLevelMedium,
			Enabled:     true,
			Description: "Detects and sanitizes Social Security Numbers",
			Categories:  []string{"pii", "privacy"},
		},
		{
			Name:        "personal_info_credit_card",
			Type:        "regex",
			Pattern:     `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
			Action:      "sanitize",
			Level:       SecurityLevelHigh,
			Enabled:     true,
			Description: "Detects and sanitizes credit card numbers",
			Categories:  []string{"pii", "financial"},
		},
		{
			Name:        "suspicious_urls",
			Type:        "regex",
			Pattern:     `(?i)https?://[^/]*\.(tk|ml|ga|cf|bit\.ly|tinyurl|short\.link)`,
			Action:      "warn",
			Level:       SecurityLevelMedium,
			Enabled:     true,
			Description: "Warns about suspicious or shortened URLs",
			Categories:  []string{"phishing", "url"},
		},
		{
			Name:        "base64_encoded_content",
			Type:        "regex",
			Pattern:     `(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?`,
			Action:      "log",
			Level:       SecurityLevelLow,
			Enabled:     true,
			Description: "Logs potential base64 encoded content",
			Categories:  []string{"encoding", "obfuscation"},
		},
		{
			Name:        "unicode_security_issues",
			Type:        "regex",
			Pattern:     `[\u202A-\u202E\u061C\u200E\u200F\u2066-\u2069]`,
			Action:      "sanitize",
			Level:       SecurityLevelMedium,
			Enabled:     true,
			Description: "Sanitizes Unicode directional override characters",
			Categories:  []string{"unicode", "security"},
		},
	}

	cf.rules = append(cf.rules, defaultRules...)
}

// ShouldFilter determines if a request should be filtered
func (cf *ContentFilter) ShouldFilter(ctx context.Context, req *http.Request) bool {
	if !cf.config.Enabled {
		return false
	}

	// Always filter POST requests with body content
	if req.Method == "POST" && req.ContentLength > 0 {
		return true
	}

	// Filter requests with specific content types
	contentType := req.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") ||
		strings.Contains(contentType, "text/") ||
		strings.Contains(contentType, "application/x-www-form-urlencoded") {
		return true
	}

	return false
}

// FilterRequest filters an HTTP request
func (cf *ContentFilter) FilterRequest(ctx context.Context, req *http.Request) (*http.Request, error) {
	if !cf.config.Enabled {
		return req, nil
	}

	// Check request size
	if cf.config.MaxRequestSize > 0 && req.ContentLength > cf.config.MaxRequestSize {
		return nil, fmt.Errorf("request size %d exceeds maximum %d", req.ContentLength, cf.config.MaxRequestSize)
	}

	// Filter URL and query parameters
	if result := cf.filterURL(req.URL.String()); !result.Allowed {
		if cf.config.StrictMode {
			return nil, fmt.Errorf("URL blocked by content filter")
		}
	}

	// Filter headers
	if result := cf.filterHeaders(req.Header); !result.Allowed {
		if cf.config.StrictMode {
			return nil, fmt.Errorf("headers blocked by content filter")
		}
	}

	// Filter body content
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()

		result := cf.filterContent(string(body), "request_body")
		if !result.Allowed {
			if cf.config.StrictMode {
				return nil, fmt.Errorf("request body blocked by content filter")
			}
		}

		// Replace body with filtered content if sanitized
		if result.Sanitized {
			filteredBody := cf.applySanitization(string(body), result.Violations)
			req.Body = io.NopCloser(strings.NewReader(filteredBody))
			req.ContentLength = int64(len(filteredBody))
		} else {
			req.Body = io.NopCloser(bytes.NewReader(body))
		}
	}

	return req, nil
}

// filterURL filters URL content
func (cf *ContentFilter) filterURL(url string) *ContentFilterResult {
	return cf.filterContent(url, "url")
}

// filterHeaders filters HTTP headers
func (cf *ContentFilter) filterHeaders(headers http.Header) *ContentFilterResult {
	result := &ContentFilterResult{
		Allowed:    true,
		Violations: make([]ContentViolation, 0),
		Metadata:   make(map[string]interface{}),
	}

	for name, values := range headers {
		for _, value := range values {
			headerResult := cf.filterContent(value, "header")
			if !headerResult.Allowed {
				result.Allowed = false
			}

			// Add header-specific context to violations
			for _, violation := range headerResult.Violations {
				violation.Location = "header"
				violation.Field = name
				result.Violations = append(result.Violations, violation)
			}
		}
	}

	return result
}

// filterContent filters text content against all rules
func (cf *ContentFilter) filterContent(content, location string) *ContentFilterResult {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	result := &ContentFilterResult{
		Allowed:      true,
		Violations:   make([]ContentViolation, 0),
		OriginalSize: int64(len(content)),
		Metadata:     make(map[string]interface{}),
	}

	for _, rule := range cf.rules {
		if !rule.Enabled {
			continue
		}

		violations := cf.applyRule(rule, content, location)
		result.Violations = append(result.Violations, violations...)

		// Determine action based on violations
		for _, violation := range violations {
			switch violation.Action {
			case "block":
				result.Allowed = false
				result.Action = "block"
			case "sanitize":
				result.Sanitized = true
				if result.Action == "" {
					result.Action = "sanitize"
				}
			case "warn":
				if result.Action == "" {
					result.Action = "warn"
				}
			case "log":
				if result.Action == "" {
					result.Action = "log"
				}
			}
		}
	}

	return result
}

// applyRule applies a single filtering rule to content
func (cf *ContentFilter) applyRule(rule ContentFilterRule, content, location string) []ContentViolation {
	var violations []ContentViolation

	switch rule.Type {
	case "regex":
		if matches := cf.findRegexMatches(rule.Pattern, content); len(matches) > 0 {
			for _, match := range matches {
				violation := ContentViolation{
					Rule:       rule.Name,
					Type:       rule.Type,
					Level:      rule.Level,
					Message:    fmt.Sprintf("Content matches rule: %s", rule.Description),
					Location:   location,
					Value:      match,
					Category:   strings.Join(rule.Categories, ","),
					Action:     rule.Action,
					Suggestion: cf.getSuggestion(rule),
				}
				violations = append(violations, violation)
			}
		}
	case "keyword":
		if matches := cf.findKeywordMatches(rule.Pattern, content); len(matches) > 0 {
			for _, match := range matches {
				violation := ContentViolation{
					Rule:       rule.Name,
					Type:       rule.Type,
					Level:      rule.Level,
					Message:    fmt.Sprintf("Content contains blocked keyword: %s", match),
					Location:   location,
					Value:      match,
					Category:   strings.Join(rule.Categories, ","),
					Action:     rule.Action,
					Suggestion: cf.getSuggestion(rule),
				}
				violations = append(violations, violation)
			}
		}
	case "mime_type", "file_extension":
		// These are handled in specific contexts
	}

	return violations
}

// findRegexMatches finds all regex matches in content
func (cf *ContentFilter) findRegexMatches(pattern, content string) []string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil
	}

	matches := re.FindAllString(content, -1)
	return matches
}

// findKeywordMatches finds all keyword matches in content
func (cf *ContentFilter) findKeywordMatches(pattern, content string) []string {
	// Keywords are treated as regex patterns for consistency
	return cf.findRegexMatches(pattern, content)
}

// applySanitization applies sanitization based on violations
func (cf *ContentFilter) applySanitization(content string, violations []ContentViolation) string {
	sanitized := content

	for _, violation := range violations {
		if violation.Action == "sanitize" {
			switch violation.Type {
			case "regex", "keyword":
				// Replace matched content with asterisks
				re, err := regexp.Compile(violation.Value)
				if err == nil {
					replacement := strings.Repeat("*", len(violation.Value))
					sanitized = re.ReplaceAllString(sanitized, replacement)
				}
			}
		}
	}

	return sanitized
}

// getSuggestion returns a suggestion for fixing the violation
func (cf *ContentFilter) getSuggestion(rule ContentFilterRule) string {
	suggestions := map[string]string{
		"malware_signatures":         "Remove or quarantine potentially malicious content",
		"suspicious_file_extensions": "Use safe file formats and validate file contents",
		"spam_keywords":              "Remove promotional language and spam indicators",
		"profanity_filter":           "Use appropriate language and remove offensive content",
		"personal_info_ssn":          "Remove or mask Social Security Numbers",
		"personal_info_credit_card":  "Remove or mask credit card numbers",
		"suspicious_urls":            "Use trusted and verified URLs only",
		"unicode_security_issues":    "Remove Unicode directional override characters",
	}

	if suggestion, exists := suggestions[rule.Name]; exists {
		return suggestion
	}

	return "Review and modify content according to security policies"
}

// AddRule adds a custom filtering rule
func (cf *ContentFilter) AddRule(rule ContentFilterRule) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	cf.rules = append(cf.rules, rule)
}

// RemoveRule removes a filtering rule by name
func (cf *ContentFilter) RemoveRule(name string) {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	for i, rule := range cf.rules {
		if rule.Name == name {
			cf.rules = append(cf.rules[:i], cf.rules[i+1:]...)
			break
		}
	}
}

// GetRules returns all filtering rules
func (cf *ContentFilter) GetRules() []ContentFilterRule {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	rules := make([]ContentFilterRule, len(cf.rules))
	copy(rules, cf.rules)
	return rules
}

// UpdateRule updates an existing rule
func (cf *ContentFilter) UpdateRule(name string, rule ContentFilterRule) bool {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	for i, existingRule := range cf.rules {
		if existingRule.Name == name {
			cf.rules[i] = rule
			return true
		}
	}

	return false
}

// EnableRule enables a rule by name
func (cf *ContentFilter) EnableRule(name string) bool {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	for i, rule := range cf.rules {
		if rule.Name == name {
			cf.rules[i].Enabled = true
			return true
		}
	}

	return false
}

// DisableRule disables a rule by name
func (cf *ContentFilter) DisableRule(name string) bool {
	cf.mu.Lock()
	defer cf.mu.Unlock()

	for i, rule := range cf.rules {
		if rule.Name == name {
			cf.rules[i].Enabled = false
			return true
		}
	}

	return false
}

// GetStats returns filtering statistics
func (cf *ContentFilter) GetStats() map[string]interface{} {
	cf.mu.RLock()
	defer cf.mu.RUnlock()

	stats := map[string]interface{}{
		"total_rules":   len(cf.rules),
		"enabled_rules": 0,
		"rule_types":    make(map[string]int),
		"categories":    make(map[string]int),
	}

	for _, rule := range cf.rules {
		if rule.Enabled {
			stats["enabled_rules"] = stats["enabled_rules"].(int) + 1
		}

		ruleTypes := stats["rule_types"].(map[string]int)
		ruleTypes[rule.Type]++

		categories := stats["categories"].(map[string]int)
		for _, category := range rule.Categories {
			categories[category]++
		}
	}

	return stats
}
