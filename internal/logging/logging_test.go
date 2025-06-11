package logging

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/dhirajsb/gomcp/pkg/features"
)

// MockOutput for testing
type MockOutput struct {
	name     string
	entries  []*LogEntry
	flushed  bool
	closed   bool
	writeErr error
}

func NewMockOutput(name string) *MockOutput {
	return &MockOutput{
		name:    name,
		entries: make([]*LogEntry, 0),
	}
}

func (m *MockOutput) Write(entry *LogEntry) error {
	if m.writeErr != nil {
		return m.writeErr
	}
	m.entries = append(m.entries, entry)
	return nil
}

func (m *MockOutput) Flush() error {
	m.flushed = true
	return nil
}

func (m *MockOutput) Close() error {
	m.closed = true
	return nil
}

func (m *MockOutput) Name() string {
	return m.name
}

func (m *MockOutput) Type() string {
	return "mock"
}

func (m *MockOutput) SetError(err error) {
	m.writeErr = err
}

func (m *MockOutput) GetEntries() []*LogEntry {
	return m.entries
}

func TestNewLogger(t *testing.T) {
	config := LoggerConfig{
		Name:  "test-logger",
		Level: features.INFO,
		Outputs: []OutputConfig{
			{
				Name:    "mock",
				Type:    "stdout",
				Enabled: true,
			},
		},
		Formatter: "json",
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if logger == nil {
		t.Fatal("Expected logger to be created")
	}

	if logger.config.Name != "test-logger" {
		t.Errorf("Expected logger name test-logger, got %s", logger.config.Name)
	}

	if logger.level != features.INFO {
		t.Errorf("Expected level info, got %v", logger.level)
	}
}

func TestLogger_BasicLogging(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.DEBUG,
		Async:   false, // Synchronous for testing
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Add mock output
	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test basic logging methods
	logger.Debug("Debug message")
	logger.Info("Info message")
	logger.Warn("Warning message")
	logger.Error("Error message")

	entries := mockOutput.GetEntries()
	if len(entries) != 4 {
		t.Errorf("Expected 4 log entries, got %d", len(entries))
	}

	expectedLevels := []features.LogLevel{features.DEBUG, features.INFO, features.WARN, features.ERROR}
	expectedMessages := []string{"Debug message", "Info message", "Warning message", "Error message"}

	for i, entry := range entries {
		if entry.Level != expectedLevels[i] {
			t.Errorf("Entry %d: expected level %v, got %v", i, expectedLevels[i], entry.Level)
		}
		if entry.Message != expectedMessages[i] {
			t.Errorf("Entry %d: expected message '%s', got '%s'", i, expectedMessages[i], entry.Message)
		}
	}
}

func TestLogger_FormattedLogging(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.DEBUG,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test formatted logging
	logger.Debugf("Debug: %s = %d", "count", 42)
	logger.Infof("Info: %s", "formatted")

	entries := mockOutput.GetEntries()
	if len(entries) != 2 {
		t.Errorf("Expected 2 log entries, got %d", len(entries))
	}

	if entries[0].Message != "Debug: count = 42" {
		t.Errorf("Expected formatted debug message, got '%s'", entries[0].Message)
	}

	if entries[1].Message != "Info: formatted" {
		t.Errorf("Expected formatted info message, got '%s'", entries[1].Message)
	}
}

func TestLogger_WithFields(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.DEBUG,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test logging with fields
	fieldLogger := logger.WithFields(
		String("user_id", "123"),
		Int("count", 42),
		Bool("active", true),
	)

	fieldLogger.Info("Message with fields")

	entries := mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Fields["user_id"] != "123" {
		t.Errorf("Expected user_id field, got %v", entry.Fields["user_id"])
	}

	if entry.Fields["count"] != 42 {
		t.Errorf("Expected count field, got %v", entry.Fields["count"])
	}

	if entry.Fields["active"] != true {
		t.Errorf("Expected active field, got %v", entry.Fields["active"])
	}
}

func TestLogger_WithContext(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.DEBUG,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Create context with values
	ctx := context.Background()
	ctx = context.WithValue(ctx, "user_id", "user123")
	ctx = context.WithValue(ctx, "request_id", "req456")

	// Test logging with context
	contextLogger := logger.WithContext(ctx)
	contextLogger.Info("Message with context")

	entries := mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Fields["user_id"] != "user123" {
		t.Errorf("Expected user_id from context, got %v", entry.Fields["user_id"])
	}

	if entry.Fields["request_id"] != "req456" {
		t.Errorf("Expected request_id from context, got %v", entry.Fields["request_id"])
	}
}

func TestLogger_WithChaining(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.DEBUG,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test method chaining
	logger.WithComponent("auth").
		WithUser("user123").
		WithSession("session456").
		WithFields(String("action", "login")).
		Info("User logged in")

	entries := mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Component != "auth" {
		t.Errorf("Expected component auth, got %s", entry.Component)
	}

	if entry.Fields["user_id"] != "user123" {
		t.Errorf("Expected user_id, got %v", entry.Fields["user_id"])
	}

	if entry.Fields["session_id"] != "session456" {
		t.Errorf("Expected session_id, got %v", entry.Fields["session_id"])
	}

	if entry.Fields["action"] != "login" {
		t.Errorf("Expected action field, got %v", entry.Fields["action"])
	}
}

func TestLogger_LogLevels(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.WARN, // Only warn and above
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test level filtering
	logger.Debug("Debug message")  // Should be filtered
	logger.Info("Info message")    // Should be filtered
	logger.Warn("Warning message") // Should pass
	logger.Error("Error message")  // Should pass

	entries := mockOutput.GetEntries()
	if len(entries) != 2 {
		t.Errorf("Expected 2 log entries (warn and error), got %d", len(entries))
	}

	if entries[0].Level != features.WARN {
		t.Errorf("Expected first entry to be warn level, got %v", entries[0].Level)
	}

	if entries[1].Level != features.ERROR {
		t.Errorf("Expected second entry to be error level, got %v", entries[1].Level)
	}
}

func TestLogger_IsEnabled(t *testing.T) {
	config := LoggerConfig{
		Name:  "test-logger",
		Level: features.WARN,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Test IsEnabled
	if logger.IsEnabled(features.DEBUG) {
		t.Error("Expected debug to be disabled")
	}

	if logger.IsEnabled(features.INFO) {
		t.Error("Expected info to be disabled")
	}

	if !logger.IsEnabled(features.WARN) {
		t.Error("Expected warn to be enabled")
	}

	if !logger.IsEnabled(features.ERROR) {
		t.Error("Expected error to be enabled")
	}

	if !logger.IsEnabled(features.FATAL) {
		t.Error("Expected fatal to be enabled")
	}
}

func TestLogger_SetLevel(t *testing.T) {
	config := LoggerConfig{
		Name:  "test-logger",
		Level: features.INFO,
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Change level
	logger.SetLevel(features.ERROR)

	if logger.GetLevel() != features.ERROR {
		t.Errorf("Expected level to be error, got %v", logger.GetLevel())
	}

	// Test that lower levels are now disabled
	if logger.IsEnabled(features.INFO) {
		t.Error("Expected info to be disabled after level change")
	}

	if !logger.IsEnabled(features.ERROR) {
		t.Error("Expected error to be enabled after level change")
	}
}

func TestLogger_Stats(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.DEBUG,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Generate some log entries
	logger.Debug("Debug message")
	logger.Info("Info message")
	logger.Warn("Warning message")
	logger.Error("Error message")

	// Get stats
	stats := logger.GetStats()

	if stats.Name != "test-logger" {
		t.Errorf("Expected stats name test-logger, got %s", stats.Name)
	}

	if stats.TotalEntries != 4 {
		t.Errorf("Expected 4 total entries, got %d", stats.TotalEntries)
	}

	if stats.EntriesByLevel[features.DEBUG] != 1 {
		t.Errorf("Expected 1 debug entry, got %d", stats.EntriesByLevel[features.DEBUG])
	}

	if stats.EntriesByLevel[features.INFO] != 1 {
		t.Errorf("Expected 1 info entry, got %d", stats.EntriesByLevel[features.INFO])
	}

	if stats.Uptime <= 0 {
		t.Error("Expected uptime to be positive")
	}
}

func TestLogger_OutputManagement(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.INFO,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	// Add output
	mockOutput := NewMockOutput("test-output")
	err = logger.AddOutput(mockOutput)
	if err != nil {
		t.Errorf("Expected no error adding output, got %v", err)
	}

	// Log a message
	logger.Info("Test message")

	entries := mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 entry, got %d", len(entries))
	}

	// Remove output
	err = logger.RemoveOutput("test-output")
	if err != nil {
		t.Errorf("Expected no error removing output, got %v", err)
	}

	// Log another message
	logger.Info("Another message")

	// Should still have only 1 entry (output was removed)
	entries = mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected still 1 entry after output removal, got %d", len(entries))
	}

	// Check that output was closed
	if !mockOutput.closed {
		t.Error("Expected output to be closed after removal")
	}
}

func TestLogger_Flush(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.INFO,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Flush logger
	err = logger.Flush()
	if err != nil {
		t.Errorf("Expected no error flushing, got %v", err)
	}

	// Check that output was flushed
	if !mockOutput.flushed {
		t.Error("Expected output to be flushed")
	}
}

func TestLogger_Close(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.INFO,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Close logger
	err = logger.Close()
	if err != nil {
		t.Errorf("Expected no error closing, got %v", err)
	}

	// Check that output was closed
	if !mockOutput.closed {
		t.Error("Expected output to be closed")
	}
}

func TestLogger_WithError(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.INFO,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test logging with error
	testErr := errors.New("test error")
	logger.WithError(testErr).Error("An error occurred")

	entries := mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(entries))
	}

	entry := entries[0]
	if entry.Fields["error"] != "test error" {
		t.Errorf("Expected error field, got %v", entry.Fields["error"])
	}
}

func TestLogger_WithTags(t *testing.T) {
	config := LoggerConfig{
		Name:    "test-logger",
		Level:   features.INFO,
		Async:   false,
		Outputs: []OutputConfig{},
	}

	logger, err := NewLogger(config)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	mockOutput := NewMockOutput("test-output")
	logger.AddOutput(mockOutput)

	// Test logging with tags
	logger.WithTags("auth", "security", "login").Info("User authentication")

	entries := mockOutput.GetEntries()
	if len(entries) != 1 {
		t.Errorf("Expected 1 log entry, got %d", len(entries))
	}

	entry := entries[0]
	tags, ok := entry.Fields["tags"].([]string)
	if !ok {
		t.Errorf("Expected tags field to be []string, got %T", entry.Fields["tags"])
	}

	expectedTags := []string{"auth", "security", "login"}
	if len(tags) != len(expectedTags) {
		t.Errorf("Expected %d tags, got %d", len(expectedTags), len(tags))
	}

	for i, tag := range expectedTags {
		if tags[i] != tag {
			t.Errorf("Expected tag %s, got %s", tag, tags[i])
		}
	}
}

func TestLogLevel_String(t *testing.T) {
	tests := []struct {
		level    features.LogLevel
		expected string
	}{
		{features.TRACE, "TRACE"},
		{features.DEBUG, "DEBUG"},
		{features.INFO, "INFO"},
		{features.WARN, "WARN"},
		{features.ERROR, "ERROR"},
		{features.FATAL, "FATAL"},
		{features.LogLevel(999), "INFO"},
	}

	for _, test := range tests {
		result := test.level.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

func TestLogEntry(t *testing.T) {
	now := time.Now()
	entry := &LogEntry{
		Timestamp: now,
		Level:     features.INFO,
		Message:   "Test message",
		Fields:    map[string]interface{}{"key": "value"},
		Logger:    "test-logger",
		Component: "test-component",
		UserID:    "user123",
		SessionID: "session456",
		RequestID: "request789",
		TraceID:   "trace-abc",
		SpanID:    "span-def",
		Duration:  100 * time.Millisecond,
		Error:     "test error",
		Tags:      []string{"tag1", "tag2"},
		Metadata:  map[string]interface{}{"meta": "data"},
	}

	if entry.Level != features.INFO {
		t.Errorf("Expected level info, got %v", entry.Level)
	}

	if entry.Message != "Test message" {
		t.Errorf("Expected message 'Test message', got %s", entry.Message)
	}

	if entry.Fields["key"] != "value" {
		t.Error("Expected field to be set")
	}

	if entry.Duration != 100*time.Millisecond {
		t.Errorf("Expected duration 100ms, got %v", entry.Duration)
	}

	if len(entry.Tags) != 2 {
		t.Errorf("Expected 2 tags, got %d", len(entry.Tags))
	}
}

func TestFieldHelpers(t *testing.T) {
	tests := []struct {
		name     string
		field    Field
		expected interface{}
	}{
		{"String", String("key", "value"), "value"},
		{"Int", Int("key", 42), 42},
		{"Int64", Int64("key", 42), int64(42)},
		{"Float64", Float64("key", 3.14), 3.14},
		{"Bool", Bool("key", true), true},
		{"Duration", Duration("key", time.Hour), time.Hour},
		{"Time", Time("key", time.Unix(1234567890, 0)), time.Unix(1234567890, 0)},
		{"Any", Any("key", "any_value"), "any_value"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.field.Key != "key" {
				t.Errorf("Expected key 'key', got %s", test.field.Key)
			}

			if test.field.Value != test.expected {
				t.Errorf("Expected value %v, got %v", test.expected, test.field.Value)
			}
		})
	}
}
