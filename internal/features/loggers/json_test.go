package loggers

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dhirajsb/gomcp/internal/logging"
)

func TestNewJSON(t *testing.T) {
	logger := NewJSON("json-logger", "warn")
	
	if logger.name != "json-logger" {
		t.Errorf("Expected name 'json-logger', got '%s'", logger.name)
	}
	
	if logger.level != logging.LogLevelWarn {
		t.Errorf("Expected level %v, got %v", logging.LogLevelWarn, logger.level)
	}
}

func TestJSONLogger_Name(t *testing.T) {
	logger := NewJSON("my-json-logger", "error")
	
	if logger.Name() != "my-json-logger" {
		t.Errorf("Expected name 'my-json-logger', got '%s'", logger.Name())
	}
}

func TestJSONLogger_Log(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewJSON("json-test", "debug")
	
	fields := map[string]interface{}{
		"user_id": "12345",
		"action":  "create_resource",
		"count":   10,
		"success": true,
	}
	
	logger.Log(logging.LogLevelInfo, "Resource created", fields)
	
	output := buf.String()
	
	// Parse the JSON output
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v, output: %s", err, output)
	}
	
	// Check required fields
	if logEntry["level"] != "INFO" {
		t.Errorf("Expected level 'INFO', got '%v'", logEntry["level"])
	}
	
	if logEntry["logger"] != "json-test" {
		t.Errorf("Expected logger 'json-test', got '%v'", logEntry["logger"])
	}
	
	if logEntry["message"] != "Resource created" {
		t.Errorf("Expected message 'Resource created', got '%v'", logEntry["message"])
	}
	
	// Check custom fields
	if logEntry["user_id"] != "12345" {
		t.Errorf("Expected user_id '12345', got '%v'", logEntry["user_id"])
	}
	
	if logEntry["action"] != "create_resource" {
		t.Errorf("Expected action 'create_resource', got '%v'", logEntry["action"])
	}
	
	// Check numeric field (JSON unmarshaling makes this float64)
	if count, ok := logEntry["count"].(float64); !ok || count != 10 {
		t.Errorf("Expected count 10, got '%v' (type %T)", logEntry["count"], logEntry["count"])
	}
	
	if logEntry["success"] != true {
		t.Errorf("Expected success true, got '%v'", logEntry["success"])
	}
	
	// Check timestamp exists and is valid
	if timestampStr, ok := logEntry["timestamp"].(string); !ok {
		t.Errorf("Expected timestamp to be string, got '%v' (type %T)", logEntry["timestamp"], logEntry["timestamp"])
	} else {
		if _, err := time.Parse(time.RFC3339, timestampStr); err != nil {
			t.Errorf("Expected valid RFC3339 timestamp, got '%s': %v", timestampStr, err)
		}
	}
}

func TestJSONLogger_LogLevels(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	// Test with warn level logger
	logger := NewJSON("test", "warn")
	
	tests := []struct {
		level     logging.LogLevel
		message   string
		shouldLog bool
	}{
		{logging.LogLevelDebug, "debug message", false}, // Should not log
		{logging.LogLevelInfo, "info message", false},   // Should not log
		{logging.LogLevelWarn, "warn message", true},    // Should log
		{logging.LogLevelError, "error message", true},  // Should log
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

func TestJSONLogger_EmptyFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewJSON("test", "info")
	
	// Test with nil fields
	logger.Log(logging.LogLevelInfo, "Test message", nil)
	
	output := buf.String()
	
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	
	if logEntry["message"] != "Test message" {
		t.Errorf("Expected message 'Test message', got '%v'", logEntry["message"])
	}
	
	// Should still have standard fields
	if logEntry["level"] == nil || logEntry["logger"] == nil || logEntry["timestamp"] == nil {
		t.Errorf("Expected standard fields to be present even with nil fields")
	}
}

func TestJSONLogger_FieldOverrides(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewJSON("test", "info")
	
	// Test with fields that override standard fields
	fields := map[string]interface{}{
		"level":     "CUSTOM_LEVEL", // This should override the level
		"timestamp": "custom-time",   // This should override the timestamp
		"message":   "custom-message", // This should override the message
	}
	
	logger.Log(logging.LogLevelInfo, "Original message", fields)
	
	output := buf.String()
	
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	
	// The custom fields should take precedence
	if logEntry["level"] != "CUSTOM_LEVEL" {
		t.Errorf("Expected custom level to override, got '%v'", logEntry["level"])
	}
	
	if logEntry["timestamp"] != "custom-time" {
		t.Errorf("Expected custom timestamp to override, got '%v'", logEntry["timestamp"])
	}
	
	if logEntry["message"] != "custom-message" {
		t.Errorf("Expected custom message to override, got '%v'", logEntry["message"])
	}
}

func TestJSONLogger_Close(t *testing.T) {
	logger := NewJSON("test", "info")
	
	err := logger.Close()
	if err != nil {
		t.Errorf("Expected Close() to return nil, got %v", err)
	}
}

func TestJSONLogger_ComplexFields(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)

	logger := NewJSON("test", "info")
	
	// Test with complex field types
	fields := map[string]interface{}{
		"nested": map[string]interface{}{
			"key": "value",
			"num": 42,
		},
		"array":  []string{"a", "b", "c"},
		"nil":    nil,
		"float":  3.14159,
	}
	
	logger.Log(logging.LogLevelInfo, "Complex fields test", fields)
	
	output := buf.String()
	
	var logEntry map[string]interface{}
	if err := json.Unmarshal([]byte(output), &logEntry); err != nil {
		t.Fatalf("Failed to parse JSON output: %v", err)
	}
	
	// Check nested object
	if nested, ok := logEntry["nested"].(map[string]interface{}); !ok {
		t.Errorf("Expected nested object, got %T", logEntry["nested"])
	} else {
		if nested["key"] != "value" {
			t.Errorf("Expected nested.key 'value', got '%v'", nested["key"])
		}
	}
	
	// Check array
	if array, ok := logEntry["array"].([]interface{}); !ok {
		t.Errorf("Expected array, got %T", logEntry["array"])
	} else {
		if len(array) != 3 || array[0] != "a" {
			t.Errorf("Expected array [a,b,c], got %v", array)
		}
	}
	
	// Check nil
	if logEntry["nil"] != nil {
		t.Errorf("Expected nil field to be nil, got %v", logEntry["nil"])
	}
	
	// Check float
	if float, ok := logEntry["float"].(float64); !ok || float != 3.14159 {
		t.Errorf("Expected float 3.14159, got %v", logEntry["float"])
	}
}