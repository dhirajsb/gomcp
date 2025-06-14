package loggers

import (
	"bytes"
	"log"
	"os"
	"strings"
	"testing"

	"github.com/dhirajsb/gomcp/pkg/features"
)

func TestNewConsole(t *testing.T) {
	logger := NewConsole("test-logger", "info")

	if logger.name != "test-logger" {
		t.Errorf("Expected name 'test-logger', got '%s'", logger.name)
	}

	if logger.level != features.INFO {
		t.Errorf("Expected level %v, got %v", features.INFO, logger.level)
	}
}

func TestConsoleLogger_Name(t *testing.T) {
	logger := NewConsole("my-logger", "debug")

	if logger.Name() != "my-logger" {
		t.Errorf("Expected name 'my-logger', got '%s'", logger.Name())
	}
}

func TestConsoleLogger_Log(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewConsole("test", "debug")

	fields := map[string]interface{}{
		"user":   "john",
		"action": "login",
	}

	logger.Log(features.INFO, "User logged in", fields)

	output := buf.String()

	// Check that the output contains expected elements
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("Expected log output to contain '[INFO]', got: %s", output)
	}

	if !strings.Contains(output, "test") {
		t.Errorf("Expected log output to contain logger name 'test', got: %s", output)
	}

	if !strings.Contains(output, "User logged in") {
		t.Errorf("Expected log output to contain message 'User logged in', got: %s", output)
	}

	if !strings.Contains(output, "user=john") {
		t.Errorf("Expected log output to contain field 'user=john', got: %s", output)
	}
}

func TestConsoleLogger_LogLevels(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test with info level logger
	logger := NewConsole("test", "info")

	tests := []struct {
		level     features.LogLevel
		message   string
		shouldLog bool
	}{
		{features.DEBUG, "debug message", false}, // Should not log
		{features.INFO, "info message", true},    // Should log
		{features.WARN, "warn message", true},    // Should log
		{features.ERROR, "error message", true},  // Should log
	}

	for _, test := range tests {
		buf.Reset()
		logger.Log(test.level, test.message, nil)

		output := buf.String()
		hasOutput := len(output) > 0 && strings.Contains(output, test.message)

		if hasOutput != test.shouldLog {
			t.Errorf("Level %v: expected shouldLog=%v, got hasOutput=%v, output: '%s'",
				test.level, test.shouldLog, hasOutput, output)
		}
	}
}

func TestConsoleLogger_Close(t *testing.T) {
	logger := NewConsole("test", "info")

	err := logger.Close()
	if err != nil {
		t.Errorf("Expected Close() to return nil, got %v", err)
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected features.LogLevel
	}{
		{"debug", features.DEBUG},
		{"DEBUG", features.DEBUG},
		{"info", features.INFO},
		{"INFO", features.INFO},
		{"warn", features.WARN},
		{"warning", features.WARN},
		{"error", features.ERROR},
		{"ERROR", features.ERROR},
		{"invalid", features.INFO}, // Default
		{"", features.INFO},        // Default
	}

	for _, test := range tests {
		result := parseLogLevel(test.input)
		if result != test.expected {
			t.Errorf("parseLogLevel(%q): expected %v, got %v", test.input, test.expected, result)
		}
	}
}

func TestConsoleLogger_WithFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewConsole("test", "info")

	fields := map[string]interface{}{
		"string_field": "value",
		"int_field":    42,
		"bool_field":   true,
		"nil_field":    nil,
	}

	logger.Log(features.INFO, "Test with fields", fields)

	output := buf.String()

	// Check that all fields are included
	expectedPairs := []string{
		"string_field=value",
		"int_field=42",
		"bool_field=true",
		"nil_field=<nil>",
	}

	for _, pair := range expectedPairs {
		if !strings.Contains(output, pair) {
			t.Errorf("Expected output to contain '%s', got: %s", pair, output)
		}
	}
}
