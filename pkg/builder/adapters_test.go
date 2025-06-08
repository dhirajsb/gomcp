package builder

import (
	"context"
	"errors"
	"testing"

	"github.com/dhirajsb/gomcp/internal/auth"
	"github.com/dhirajsb/gomcp/internal/logging"
	"github.com/dhirajsb/gomcp/internal/types"
	"github.com/dhirajsb/gomcp/pkg/features"
)

// Mock internal logger for testing
type MockInternalLogger struct {
	name   string
	logs   []LogEntry
	closed bool
}

type LogEntry struct {
	Level   logging.LogLevel
	Message string
	Fields  map[string]interface{}
}

func (m *MockInternalLogger) Name() string {
	return m.name
}

func (m *MockInternalLogger) Log(level logging.LogLevel, message string, fields map[string]interface{}) {
	m.logs = append(m.logs, LogEntry{
		Level:   level,
		Message: message,
		Fields:  fields,
	})
}

func (m *MockInternalLogger) Close() error {
	if m.closed {
		return errors.New("already closed")
	}
	m.closed = true
	return nil
}

func TestLoggerAdapter_Name(t *testing.T) {
	mockLogger := &MockInternalLogger{name: "test-logger"}
	adapter := &LoggerAdapter{internal: mockLogger}
	
	if adapter.Name() != "test-logger" {
		t.Errorf("Expected name 'test-logger', got '%s'", adapter.Name())
	}
}

func TestLoggerAdapter_Log_StringLevel(t *testing.T) {
	mockLogger := &MockInternalLogger{name: "test"}
	adapter := &LoggerAdapter{internal: mockLogger}
	
	fields := map[string]interface{}{
		"user": "john",
		"id":   123,
	}
	
	// Test string levels
	stringLevels := map[string]logging.LogLevel{
		"debug":   logging.LogLevelDebug,
		"DEBUG":   logging.LogLevelDebug,
		"info":    logging.LogLevelInfo,
		"INFO":    logging.LogLevelInfo,
		"warn":    logging.LogLevelWarn,
		"WARNING": logging.LogLevelWarn,
		"WARN":    logging.LogLevelWarn,
		"error":   logging.LogLevelError,
		"ERROR":   logging.LogLevelError,
	}
	
	for strLevel, expectedLevel := range stringLevels {
		adapter.Log(strLevel, "test message", fields)
		
		if len(mockLogger.logs) == 0 {
			t.Fatalf("Expected log entry to be created for level '%s'", strLevel)
		}
		
		lastLog := mockLogger.logs[len(mockLogger.logs)-1]
		if lastLog.Level != expectedLevel {
			t.Errorf("Expected level %v for string '%s', got %v", expectedLevel, strLevel, lastLog.Level)
		}
		
		if lastLog.Message != "test message" {
			t.Errorf("Expected message 'test message', got '%s'", lastLog.Message)
		}
	}
}

func TestLoggerAdapter_Log_LogLevelType(t *testing.T) {
	mockLogger := &MockInternalLogger{name: "test"}
	adapter := &LoggerAdapter{internal: mockLogger}
	
	// Test with actual LogLevel type
	adapter.Log(logging.LogLevelError, "error message", nil)
	
	if len(mockLogger.logs) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(mockLogger.logs))
	}
	
	logEntry := mockLogger.logs[0]
	if logEntry.Level != logging.LogLevelError {
		t.Errorf("Expected level %v, got %v", logging.LogLevelError, logEntry.Level)
	}
	
	if logEntry.Message != "error message" {
		t.Errorf("Expected message 'error message', got '%s'", logEntry.Message)
	}
}

func TestLoggerAdapter_Log_UnknownLevel(t *testing.T) {
	mockLogger := &MockInternalLogger{name: "test"}
	adapter := &LoggerAdapter{internal: mockLogger}
	
	// Test with unknown level - should default to info
	adapter.Log("unknown-level", "test message", nil)
	
	if len(mockLogger.logs) != 1 {
		t.Fatalf("Expected 1 log entry, got %d", len(mockLogger.logs))
	}
	
	logEntry := mockLogger.logs[0]
	if logEntry.Level != logging.LogLevelInfo {
		t.Errorf("Expected default level %v, got %v", logging.LogLevelInfo, logEntry.Level)
	}
}

func TestLoggerAdapter_Log_InterfaceLevel(t *testing.T) {
	mockLogger := &MockInternalLogger{name: "test"}
	adapter := &LoggerAdapter{internal: mockLogger}
	
	// Test with other interface types - should default to info
	adapter.Log(123, "test message", nil)
	adapter.Log([]string{"level"}, "test message", nil)
	adapter.Log(nil, "test message", nil)
	
	if len(mockLogger.logs) != 3 {
		t.Fatalf("Expected 3 log entries, got %d", len(mockLogger.logs))
	}
	
	for i, logEntry := range mockLogger.logs {
		if logEntry.Level != logging.LogLevelInfo {
			t.Errorf("Entry %d: Expected default level %v, got %v", i, logging.LogLevelInfo, logEntry.Level)
		}
	}
}

func TestLoggerAdapter_Close(t *testing.T) {
	mockLogger := &MockInternalLogger{name: "test"}
	adapter := &LoggerAdapter{internal: mockLogger}
	
	err := adapter.Close()
	if err != nil {
		t.Errorf("Expected no error from close, got %v", err)
	}
	
	if !mockLogger.closed {
		t.Error("Expected internal logger to be closed")
	}
	
	// Second close should return error
	err = adapter.Close()
	if err == nil {
		t.Error("Expected error from second close")
	}
}

// Mock internal authenticator for testing
type MockInternalAuthenticator struct {
	name  string
	users map[string]*auth.UserIdentity
}

func (m *MockInternalAuthenticator) Name() string {
	return m.name
}

func (m *MockInternalAuthenticator) Authenticate(ctx context.Context, token string) (*auth.UserIdentity, error) {
	user, exists := m.users[token]
	if !exists {
		return nil, errors.New("invalid token")
	}
	return user, nil
}

func (m *MockInternalAuthenticator) Validate(ctx context.Context, user *auth.UserIdentity) error {
	if user == nil || user.ID == "" {
		return errors.New("invalid user")
	}
	return nil
}

func TestAuthenticatorAdapter_Name(t *testing.T) {
	mockAuth := &MockInternalAuthenticator{name: "test-auth"}
	adapter := &AuthenticatorAdapter{internal: mockAuth}
	
	if adapter.Name() != "test-auth" {
		t.Errorf("Expected name 'test-auth', got '%s'", adapter.Name())
	}
}

func TestAuthenticatorAdapter_Authenticate_Success(t *testing.T) {
	internalUser := &auth.UserIdentity{
		ID:       "user123",
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user", "admin"},
		Groups:   []string{"developers"},
		Claims:   map[string]interface{}{"custom": "value"},
	}
	
	mockAuth := &MockInternalAuthenticator{
		name:  "test",
		users: map[string]*auth.UserIdentity{"valid-token": internalUser},
	}
	adapter := &AuthenticatorAdapter{internal: mockAuth}
	
	ctx := context.Background()
	user, err := adapter.Authenticate(ctx, "valid-token")
	
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	
	if user == nil {
		t.Fatal("Expected user to be returned, got nil")
	}
	
	// Check that internal user was converted to public user correctly
	if user.ID != internalUser.ID {
		t.Errorf("Expected ID '%s', got '%s'", internalUser.ID, user.ID)
	}
	
	if user.Username != internalUser.Username {
		t.Errorf("Expected username '%s', got '%s'", internalUser.Username, user.Username)
	}
	
	if user.Email != internalUser.Email {
		t.Errorf("Expected email '%s', got '%s'", internalUser.Email, user.Email)
	}
	
	if len(user.Roles) != len(internalUser.Roles) {
		t.Errorf("Expected %d roles, got %d", len(internalUser.Roles), len(user.Roles))
	}
	
	if len(user.Groups) != len(internalUser.Groups) {
		t.Errorf("Expected %d groups, got %d", len(internalUser.Groups), len(user.Groups))
	}
	
	if user.Claims["custom"] != "value" {
		t.Errorf("Expected custom claim 'value', got '%v'", user.Claims["custom"])
	}
}

func TestAuthenticatorAdapter_Authenticate_Failure(t *testing.T) {
	mockAuth := &MockInternalAuthenticator{
		name:  "test",
		users: map[string]*auth.UserIdentity{},
	}
	adapter := &AuthenticatorAdapter{internal: mockAuth}
	
	ctx := context.Background()
	user, err := adapter.Authenticate(ctx, "invalid-token")
	
	if err == nil {
		t.Error("Expected error for invalid token, got nil")
	}
	
	if user != nil {
		t.Error("Expected nil user for invalid token")
	}
}

func TestAuthenticatorAdapter_Validate_Success(t *testing.T) {
	mockAuth := &MockInternalAuthenticator{name: "test"}
	adapter := &AuthenticatorAdapter{internal: mockAuth}
	
	publicUser := &features.UserIdentity{
		ID:       "user123",
		Username: "testuser",
		Email:    "test@example.com",
		Roles:    []string{"user"},
		Groups:   []string{"group1"},
		Claims:   map[string]interface{}{"key": "value"},
	}
	
	ctx := context.Background()
	err := adapter.Validate(ctx, publicUser)
	
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestAuthenticatorAdapter_Validate_Failure(t *testing.T) {
	mockAuth := &MockInternalAuthenticator{name: "test"}
	adapter := &AuthenticatorAdapter{internal: mockAuth}
	
	// Test with invalid user
	invalidUser := &features.UserIdentity{
		ID: "", // Empty ID should cause validation to fail
	}
	
	ctx := context.Background()
	err := adapter.Validate(ctx, invalidUser)
	
	if err == nil {
		t.Error("Expected error for invalid user, got nil")
	}
}

// Mock internal security validator for testing
type MockInternalSecurityValidator struct {
	name           string
	shouldReject   bool
	sanitizedValue string
}

func (m *MockInternalSecurityValidator) Name() string {
	return m.name
}

func (m *MockInternalSecurityValidator) ValidateRequest(ctx context.Context, req *types.Request) error {
	if m.shouldReject {
		return errors.New("validation failed")
	}
	return nil
}

func (m *MockInternalSecurityValidator) SanitizeParams(params map[string]interface{}) map[string]interface{} {
	if params == nil {
		return map[string]interface{}{}
	}
	
	result := make(map[string]interface{})
	for k, v := range params {
		if m.sanitizedValue != "" {
			result[k] = m.sanitizedValue
		} else {
			result[k] = v
		}
	}
	return result
}

func TestSecurityValidatorAdapter_Name(t *testing.T) {
	mockValidator := &MockInternalSecurityValidator{name: "test-security"}
	adapter := &SecurityValidatorAdapter{internal: mockValidator}
	
	if adapter.Name() != "test-security" {
		t.Errorf("Expected name 'test-security', got '%s'", adapter.Name())
	}
}

func TestSecurityValidatorAdapter_ValidateRequest_Success(t *testing.T) {
	mockValidator := &MockInternalSecurityValidator{
		name:         "test",
		shouldReject: false,
	}
	adapter := &SecurityValidatorAdapter{internal: mockValidator}
	
	publicReq := &features.Request{
		Method: "tools/list",
		Params: map[string]interface{}{"safe": "parameter"},
	}
	
	ctx := context.Background()
	err := adapter.ValidateRequest(ctx, publicReq)
	
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}
}

func TestSecurityValidatorAdapter_ValidateRequest_Failure(t *testing.T) {
	mockValidator := &MockInternalSecurityValidator{
		name:         "test",
		shouldReject: true,
	}
	adapter := &SecurityValidatorAdapter{internal: mockValidator}
	
	publicReq := &features.Request{
		Method: "malicious/method",
		Params: map[string]interface{}{"malicious": "parameter"},
	}
	
	ctx := context.Background()
	err := adapter.ValidateRequest(ctx, publicReq)
	
	if err == nil {
		t.Error("Expected error for malicious request, got nil")
	}
}

func TestSecurityValidatorAdapter_SanitizeParams(t *testing.T) {
	mockValidator := &MockInternalSecurityValidator{
		name:           "test",
		sanitizedValue: "SANITIZED",
	}
	adapter := &SecurityValidatorAdapter{internal: mockValidator}
	
	params := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	
	sanitized := adapter.SanitizeParams(params)
	
	if len(sanitized) != 2 {
		t.Errorf("Expected 2 sanitized params, got %d", len(sanitized))
	}
	
	for key, value := range sanitized {
		if value != "SANITIZED" {
			t.Errorf("Expected sanitized value for key '%s', got '%v'", key, value)
		}
	}
}

func TestSecurityValidatorAdapter_SanitizeParams_Nil(t *testing.T) {
	mockValidator := &MockInternalSecurityValidator{name: "test"}
	adapter := &SecurityValidatorAdapter{internal: mockValidator}
	
	sanitized := adapter.SanitizeParams(nil)
	
	if sanitized == nil {
		t.Error("Expected non-nil result for nil params")
	}
	
	if len(sanitized) != 0 {
		t.Errorf("Expected empty result for nil params, got %d items", len(sanitized))
	}
}

func TestWrapperFunctions(t *testing.T) {
	// Test wrapLogger
	mockLogger := &MockInternalLogger{name: "test"}
	wrappedLogger := wrapLogger(mockLogger)
	
	if wrappedLogger == nil {
		t.Error("Expected wrapLogger to return non-nil adapter")
	}
	
	if wrappedLogger.Name() != "test" {
		t.Errorf("Expected wrapped logger name 'test', got '%s'", wrappedLogger.Name())
	}
	
	// Test wrapAuthenticator
	mockAuth := &MockInternalAuthenticator{name: "test-auth"}
	wrappedAuth := wrapAuthenticator(mockAuth)
	
	if wrappedAuth == nil {
		t.Error("Expected wrapAuthenticator to return non-nil adapter")
	}
	
	if wrappedAuth.Name() != "test-auth" {
		t.Errorf("Expected wrapped auth name 'test-auth', got '%s'", wrappedAuth.Name())
	}
	
	// Test wrapSecurityValidator
	mockValidator := &MockInternalSecurityValidator{name: "test-security"}
	wrappedValidator := wrapSecurityValidator(mockValidator)
	
	if wrappedValidator == nil {
		t.Error("Expected wrapSecurityValidator to return non-nil adapter")
	}
	
	if wrappedValidator.Name() != "test-security" {
		t.Errorf("Expected wrapped validator name 'test-security', got '%s'", wrappedValidator.Name())
	}
}

func TestAdapters_ContextPropagation(t *testing.T) {
	// Test that context is properly propagated through adapters
	
	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	
	// AuthenticatorAdapter
	mockAuth := &MockInternalAuthenticator{name: "test"}
	authAdapter := &AuthenticatorAdapter{internal: mockAuth}
	
	_, err := authAdapter.Authenticate(ctx, "token")
	// Should not panic and may return context.Canceled or the original error
	_ = err
	
	// SecurityValidatorAdapter
	mockValidator := &MockInternalSecurityValidator{name: "test"}
	securityAdapter := &SecurityValidatorAdapter{internal: mockValidator}
	
	req := &features.Request{Method: "test", Params: nil}
	err = securityAdapter.ValidateRequest(ctx, req)
	// Should not panic and may return context.Canceled or the original error
	_ = err
}