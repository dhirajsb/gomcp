package security

import (
	"sync"
	"sync/atomic"
	"time"
)

// SecurityMetrics provides security validation performance metrics
type SecurityMetrics struct {
	// Validation counters
	ValidationsTotal   int64 `json:"validations_total"`
	ValidationsClean   int64 `json:"validations_clean"`
	ValidationsBlocked int64 `json:"validations_blocked"`

	// Validator-specific counters
	SQLInjectionChecks      int64 `json:"sql_injection_checks"`
	SQLInjectionBlocked     int64 `json:"sql_injection_blocked"`
	XSSChecks               int64 `json:"xss_checks"`
	XSSBlocked              int64 `json:"xss_blocked"`
	PathTraversalChecks     int64 `json:"path_traversal_checks"`
	PathTraversalBlocked    int64 `json:"path_traversal_blocked"`
	CommandInjectionChecks  int64 `json:"command_injection_checks"`
	CommandInjectionBlocked int64 `json:"command_injection_blocked"`
	InputValidationChecks   int64 `json:"input_validation_checks"`
	InputValidationBlocked  int64 `json:"input_validation_blocked"`

	// Performance timing (in nanoseconds)
	SQLInjectionLatencySum       int64 `json:"sql_injection_latency_sum_ns"`
	SQLInjectionLatencyCount     int64 `json:"sql_injection_latency_count"`
	XSSLatencySum                int64 `json:"xss_latency_sum_ns"`
	XSSLatencyCount              int64 `json:"xss_latency_count"`
	PathTraversalLatencySum      int64 `json:"path_traversal_latency_sum_ns"`
	PathTraversalLatencyCount    int64 `json:"path_traversal_latency_count"`
	CommandInjectionLatencySum   int64 `json:"command_injection_latency_sum_ns"`
	CommandInjectionLatencyCount int64 `json:"command_injection_latency_count"`
	InputValidationLatencySum    int64 `json:"input_validation_latency_sum_ns"`
	InputValidationLatencyCount  int64 `json:"input_validation_latency_count"`

	// Sanitization metrics
	SanitizationsTotal int64 `json:"sanitizations_total"`
	SQLSanitizations   int64 `json:"sql_sanitizations"`
	XSSSanitizations   int64 `json:"xss_sanitizations"`

	// Threat detection
	ThreatLevel1 int64 `json:"threat_level_1"` // Low
	ThreatLevel2 int64 `json:"threat_level_2"` // Medium
	ThreatLevel3 int64 `json:"threat_level_3"` // High
	ThreatLevel4 int64 `json:"threat_level_4"` // Critical

	// Security scores
	SecurityScoreSum   int64 `json:"security_score_sum"`
	SecurityScoreCount int64 `json:"security_score_count"`

	// Error tracking
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error"`
	LastErrorTime time.Time `json:"last_error_time"`

	// Content filtering metrics
	ContentScanned    int64 `json:"content_scanned"`
	MalwareDetected   int64 `json:"malware_detected"`
	PIIDetected       int64 `json:"pii_detected"`
	ProfanityDetected int64 `json:"profanity_detected"`

	// Start time for uptime calculation
	StartTime time.Time `json:"start_time"`

	mu sync.RWMutex
}

// ValidatorMetrics tracks metrics for individual validators
type ValidatorMetrics struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Checks       int64     `json:"checks"`
	Blocks       int64     `json:"blocks"`
	AvgLatency   float64   `json:"avg_latency_ms"`
	LastCheck    time.Time `json:"last_check"`
	BlockRate    float64   `json:"block_rate"`
	TotalLatency int64     `json:"total_latency_ns"`
}

// NewSecurityMetrics creates a new security metrics instance
func NewSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{
		StartTime: time.Now(),
	}
}

// RecordValidation records a security validation
func (m *SecurityMetrics) RecordValidation(validatorType string, blocked bool, latency time.Duration, threatLevel SecurityLevel) {
	atomic.AddInt64(&m.ValidationsTotal, 1)

	if blocked {
		atomic.AddInt64(&m.ValidationsBlocked, 1)
	} else {
		atomic.AddInt64(&m.ValidationsClean, 1)
	}

	// Record validator-specific metrics
	switch validatorType {
	case "sql_injection":
		atomic.AddInt64(&m.SQLInjectionChecks, 1)
		if blocked {
			atomic.AddInt64(&m.SQLInjectionBlocked, 1)
		}
		atomic.AddInt64(&m.SQLInjectionLatencySum, int64(latency))
		atomic.AddInt64(&m.SQLInjectionLatencyCount, 1)
	case "xss":
		atomic.AddInt64(&m.XSSChecks, 1)
		if blocked {
			atomic.AddInt64(&m.XSSBlocked, 1)
		}
		atomic.AddInt64(&m.XSSLatencySum, int64(latency))
		atomic.AddInt64(&m.XSSLatencyCount, 1)
	case "path_traversal":
		atomic.AddInt64(&m.PathTraversalChecks, 1)
		if blocked {
			atomic.AddInt64(&m.PathTraversalBlocked, 1)
		}
		atomic.AddInt64(&m.PathTraversalLatencySum, int64(latency))
		atomic.AddInt64(&m.PathTraversalLatencyCount, 1)
	case "command_injection":
		atomic.AddInt64(&m.CommandInjectionChecks, 1)
		if blocked {
			atomic.AddInt64(&m.CommandInjectionBlocked, 1)
		}
		atomic.AddInt64(&m.CommandInjectionLatencySum, int64(latency))
		atomic.AddInt64(&m.CommandInjectionLatencyCount, 1)
	case "input_validation":
		atomic.AddInt64(&m.InputValidationChecks, 1)
		if blocked {
			atomic.AddInt64(&m.InputValidationBlocked, 1)
		}
		atomic.AddInt64(&m.InputValidationLatencySum, int64(latency))
		atomic.AddInt64(&m.InputValidationLatencyCount, 1)
	}

	// Record threat level
	switch threatLevel {
	case SecurityLevelLow:
		atomic.AddInt64(&m.ThreatLevel1, 1)
	case SecurityLevelMedium:
		atomic.AddInt64(&m.ThreatLevel2, 1)
	case SecurityLevelHigh:
		atomic.AddInt64(&m.ThreatLevel3, 1)
	case SecurityLevelCritical:
		atomic.AddInt64(&m.ThreatLevel4, 1)
	}
}

// RecordSanitization records a sanitization action
func (m *SecurityMetrics) RecordSanitization(validatorType string) {
	atomic.AddInt64(&m.SanitizationsTotal, 1)

	switch validatorType {
	case "sql_injection":
		atomic.AddInt64(&m.SQLSanitizations, 1)
	case "xss":
		atomic.AddInt64(&m.XSSSanitizations, 1)
	}
}

// RecordSecurityScore records a security score
func (m *SecurityMetrics) RecordSecurityScore(score int) {
	atomic.AddInt64(&m.SecurityScoreSum, int64(score))
	atomic.AddInt64(&m.SecurityScoreCount, 1)
}

// RecordError records a security validation error
func (m *SecurityMetrics) RecordError(err error) {
	atomic.AddInt64(&m.ErrorCount, 1)

	m.mu.Lock()
	m.LastError = err.Error()
	m.LastErrorTime = time.Now()
	m.mu.Unlock()
}

// RecordContentScan records content scanning results
func (m *SecurityMetrics) RecordContentScan(malware, pii, profanity bool) {
	atomic.AddInt64(&m.ContentScanned, 1)

	if malware {
		atomic.AddInt64(&m.MalwareDetected, 1)
	}
	if pii {
		atomic.AddInt64(&m.PIIDetected, 1)
	}
	if profanity {
		atomic.AddInt64(&m.ProfanityDetected, 1)
	}
}

// GetStats returns current security statistics
func (m *SecurityMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	validationsTotal := atomic.LoadInt64(&m.ValidationsTotal)
	validationsBlocked := atomic.LoadInt64(&m.ValidationsBlocked)
	validationsClean := atomic.LoadInt64(&m.ValidationsClean)

	// Calculate rates
	var blockRate float64
	if validationsTotal > 0 {
		blockRate = float64(validationsBlocked) / float64(validationsTotal)
	}

	// Calculate average security score
	var avgSecurityScore float64
	if count := atomic.LoadInt64(&m.SecurityScoreCount); count > 0 {
		avgSecurityScore = float64(atomic.LoadInt64(&m.SecurityScoreSum)) / float64(count)
	}

	// Calculate average latencies
	avgLatencies := make(map[string]float64)

	if count := atomic.LoadInt64(&m.SQLInjectionLatencyCount); count > 0 {
		avgLatencies["sql_injection"] = float64(atomic.LoadInt64(&m.SQLInjectionLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.XSSLatencyCount); count > 0 {
		avgLatencies["xss"] = float64(atomic.LoadInt64(&m.XSSLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.PathTraversalLatencyCount); count > 0 {
		avgLatencies["path_traversal"] = float64(atomic.LoadInt64(&m.PathTraversalLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.CommandInjectionLatencyCount); count > 0 {
		avgLatencies["command_injection"] = float64(atomic.LoadInt64(&m.CommandInjectionLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.InputValidationLatencyCount); count > 0 {
		avgLatencies["input_validation"] = float64(atomic.LoadInt64(&m.InputValidationLatencySum)) / float64(count) / 1000000.0
	}

	// Calculate block rates by validator
	blockRates := make(map[string]float64)

	if checks := atomic.LoadInt64(&m.SQLInjectionChecks); checks > 0 {
		blockRates["sql_injection"] = float64(atomic.LoadInt64(&m.SQLInjectionBlocked)) / float64(checks)
	}
	if checks := atomic.LoadInt64(&m.XSSChecks); checks > 0 {
		blockRates["xss"] = float64(atomic.LoadInt64(&m.XSSBlocked)) / float64(checks)
	}
	if checks := atomic.LoadInt64(&m.PathTraversalChecks); checks > 0 {
		blockRates["path_traversal"] = float64(atomic.LoadInt64(&m.PathTraversalBlocked)) / float64(checks)
	}
	if checks := atomic.LoadInt64(&m.CommandInjectionChecks); checks > 0 {
		blockRates["command_injection"] = float64(atomic.LoadInt64(&m.CommandInjectionBlocked)) / float64(checks)
	}
	if checks := atomic.LoadInt64(&m.InputValidationChecks); checks > 0 {
		blockRates["input_validation"] = float64(atomic.LoadInt64(&m.InputValidationBlocked)) / float64(checks)
	}

	return map[string]interface{}{
		"validations_total":         validationsTotal,
		"validations_clean":         validationsClean,
		"validations_blocked":       validationsBlocked,
		"block_rate":                blockRate,
		"sql_injection_checks":      atomic.LoadInt64(&m.SQLInjectionChecks),
		"sql_injection_blocked":     atomic.LoadInt64(&m.SQLInjectionBlocked),
		"xss_checks":                atomic.LoadInt64(&m.XSSChecks),
		"xss_blocked":               atomic.LoadInt64(&m.XSSBlocked),
		"path_traversal_checks":     atomic.LoadInt64(&m.PathTraversalChecks),
		"path_traversal_blocked":    atomic.LoadInt64(&m.PathTraversalBlocked),
		"command_injection_checks":  atomic.LoadInt64(&m.CommandInjectionChecks),
		"command_injection_blocked": atomic.LoadInt64(&m.CommandInjectionBlocked),
		"input_validation_checks":   atomic.LoadInt64(&m.InputValidationChecks),
		"input_validation_blocked":  atomic.LoadInt64(&m.InputValidationBlocked),
		"avg_latencies_ms":          avgLatencies,
		"block_rates":               blockRates,
		"sanitizations_total":       atomic.LoadInt64(&m.SanitizationsTotal),
		"sql_sanitizations":         atomic.LoadInt64(&m.SQLSanitizations),
		"xss_sanitizations":         atomic.LoadInt64(&m.XSSSanitizations),
		"threat_level_1":            atomic.LoadInt64(&m.ThreatLevel1),
		"threat_level_2":            atomic.LoadInt64(&m.ThreatLevel2),
		"threat_level_3":            atomic.LoadInt64(&m.ThreatLevel3),
		"threat_level_4":            atomic.LoadInt64(&m.ThreatLevel4),
		"avg_security_score":        avgSecurityScore,
		"error_count":               atomic.LoadInt64(&m.ErrorCount),
		"last_error":                m.LastError,
		"last_error_time":           m.LastErrorTime,
		"content_scanned":           atomic.LoadInt64(&m.ContentScanned),
		"malware_detected":          atomic.LoadInt64(&m.MalwareDetected),
		"pii_detected":              atomic.LoadInt64(&m.PIIDetected),
		"profanity_detected":        atomic.LoadInt64(&m.ProfanityDetected),
		"uptime":                    time.Since(m.StartTime),
	}
}

// GetValidatorStats returns detailed validator statistics
func (m *SecurityMetrics) GetValidatorStats() map[string]*ValidatorMetrics {
	stats := make(map[string]*ValidatorMetrics)

	// SQL Injection validator
	sqlChecks := atomic.LoadInt64(&m.SQLInjectionChecks)
	if sqlChecks > 0 {
		stats["sql_injection"] = &ValidatorMetrics{
			Name:      "SQL Injection Validator",
			Type:      "sql_injection",
			Checks:    sqlChecks,
			Blocks:    atomic.LoadInt64(&m.SQLInjectionBlocked),
			BlockRate: float64(atomic.LoadInt64(&m.SQLInjectionBlocked)) / float64(sqlChecks),
		}
		if count := atomic.LoadInt64(&m.SQLInjectionLatencyCount); count > 0 {
			stats["sql_injection"].AvgLatency = float64(atomic.LoadInt64(&m.SQLInjectionLatencySum)) / float64(count) / 1000000.0
		}
	}

	// XSS validator
	xssChecks := atomic.LoadInt64(&m.XSSChecks)
	if xssChecks > 0 {
		stats["xss"] = &ValidatorMetrics{
			Name:      "XSS Validator",
			Type:      "xss",
			Checks:    xssChecks,
			Blocks:    atomic.LoadInt64(&m.XSSBlocked),
			BlockRate: float64(atomic.LoadInt64(&m.XSSBlocked)) / float64(xssChecks),
		}
		if count := atomic.LoadInt64(&m.XSSLatencyCount); count > 0 {
			stats["xss"].AvgLatency = float64(atomic.LoadInt64(&m.XSSLatencySum)) / float64(count) / 1000000.0
		}
	}

	// Path Traversal validator
	pathChecks := atomic.LoadInt64(&m.PathTraversalChecks)
	if pathChecks > 0 {
		stats["path_traversal"] = &ValidatorMetrics{
			Name:      "Path Traversal Validator",
			Type:      "path_traversal",
			Checks:    pathChecks,
			Blocks:    atomic.LoadInt64(&m.PathTraversalBlocked),
			BlockRate: float64(atomic.LoadInt64(&m.PathTraversalBlocked)) / float64(pathChecks),
		}
		if count := atomic.LoadInt64(&m.PathTraversalLatencyCount); count > 0 {
			stats["path_traversal"].AvgLatency = float64(atomic.LoadInt64(&m.PathTraversalLatencySum)) / float64(count) / 1000000.0
		}
	}

	// Command Injection validator
	cmdChecks := atomic.LoadInt64(&m.CommandInjectionChecks)
	if cmdChecks > 0 {
		stats["command_injection"] = &ValidatorMetrics{
			Name:      "Command Injection Validator",
			Type:      "command_injection",
			Checks:    cmdChecks,
			Blocks:    atomic.LoadInt64(&m.CommandInjectionBlocked),
			BlockRate: float64(atomic.LoadInt64(&m.CommandInjectionBlocked)) / float64(cmdChecks),
		}
		if count := atomic.LoadInt64(&m.CommandInjectionLatencyCount); count > 0 {
			stats["command_injection"].AvgLatency = float64(atomic.LoadInt64(&m.CommandInjectionLatencySum)) / float64(count) / 1000000.0
		}
	}

	// Input Validation validator
	inputChecks := atomic.LoadInt64(&m.InputValidationChecks)
	if inputChecks > 0 {
		stats["input_validation"] = &ValidatorMetrics{
			Name:      "Input Validation Validator",
			Type:      "input_validation",
			Checks:    inputChecks,
			Blocks:    atomic.LoadInt64(&m.InputValidationBlocked),
			BlockRate: float64(atomic.LoadInt64(&m.InputValidationBlocked)) / float64(inputChecks),
		}
		if count := atomic.LoadInt64(&m.InputValidationLatencyCount); count > 0 {
			stats["input_validation"].AvgLatency = float64(atomic.LoadInt64(&m.InputValidationLatencySum)) / float64(count) / 1000000.0
		}
	}

	return stats
}
