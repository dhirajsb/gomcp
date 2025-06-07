package types

import (
	"encoding/json"
	"testing"
)

func TestMessageSerialization(t *testing.T) {
	// Test Request serialization
	req := Request{
		Message: Message{
			JSONRPC: "2.0",
			ID:      1,
		},
		Method: "test/method",
		Params: map[string]interface{}{
			"param1": "value1",
			"param2": 42,
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Errorf("Failed to marshal request: %v", err)
	}

	var unmarshaled Request
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal request: %v", err)
	}

	if unmarshaled.JSONRPC != "2.0" {
		t.Errorf("Expected JSONRPC '2.0', got '%s'", unmarshaled.JSONRPC)
	}

	if unmarshaled.Method != "test/method" {
		t.Errorf("Expected method 'test/method', got '%s'", unmarshaled.Method)
	}
}

func TestResponseSerialization(t *testing.T) {
	// Test successful response
	resp := Response{
		Message: Message{
			JSONRPC: "2.0",
			ID:      1,
		},
		Result: map[string]interface{}{
			"success": true,
			"data":    "test data",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Errorf("Failed to marshal response: %v", err)
	}

	var unmarshaled Response
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal response: %v", err)
	}

	if unmarshaled.JSONRPC != "2.0" {
		t.Errorf("Expected JSONRPC '2.0', got '%s'", unmarshaled.JSONRPC)
	}

	if unmarshaled.Error != nil {
		t.Error("Expected no error in successful response")
	}
}

func TestErrorResponseSerialization(t *testing.T) {
	// Test error response
	resp := Response{
		Message: Message{
			JSONRPC: "2.0",
			ID:      1,
		},
		Error: &RPCError{
			Code:    ErrCodeMethodNotFound,
			Message: "Method not found",
			Data:    "additional error data",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Errorf("Failed to marshal error response: %v", err)
	}

	var unmarshaled Response
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal error response: %v", err)
	}

	if unmarshaled.Result != nil {
		t.Error("Expected no result in error response")
	}

	if unmarshaled.Error == nil {
		t.Error("Expected error in error response")
	}

	if unmarshaled.Error.Code != ErrCodeMethodNotFound {
		t.Errorf("Expected error code %d, got %d", ErrCodeMethodNotFound, unmarshaled.Error.Code)
	}
}

func TestToolSerialization(t *testing.T) {
	tool := Tool{
		Name:        "test_tool",
		Description: "A test tool",
		InputSchema: JSONSchema{
			Type: "object",
			Properties: map[string]*JSONSchema{
				"param1": {
					Type:        "string",
					Description: "First parameter",
				},
				"param2": {
					Type:        "integer",
					Description: "Second parameter",
					Minimum:     &[]float64{0}[0],
					Maximum:     &[]float64{100}[0],
				},
			},
			Required: []string{"param1"},
		},
	}

	data, err := json.Marshal(tool)
	if err != nil {
		t.Errorf("Failed to marshal tool: %v", err)
	}

	var unmarshaled Tool
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal tool: %v", err)
	}

	if unmarshaled.Name != "test_tool" {
		t.Errorf("Expected name 'test_tool', got '%s'", unmarshaled.Name)
	}

	if unmarshaled.InputSchema.Type != "object" {
		t.Errorf("Expected schema type 'object', got '%s'", unmarshaled.InputSchema.Type)
	}

	if len(unmarshaled.InputSchema.Properties) != 2 {
		t.Errorf("Expected 2 properties, got %d", len(unmarshaled.InputSchema.Properties))
	}

	if len(unmarshaled.InputSchema.Required) != 1 {
		t.Errorf("Expected 1 required field, got %d", len(unmarshaled.InputSchema.Required))
	}
}

func TestResourceSerialization(t *testing.T) {
	resource := Resource{
		URI:         "file://test.txt",
		Name:        "test_resource",
		Description: "A test resource",
		MimeType:    "text/plain",
		Annotations: map[string]string{
			"category": "test",
			"version":  "1.0",
		},
	}

	data, err := json.Marshal(resource)
	if err != nil {
		t.Errorf("Failed to marshal resource: %v", err)
	}

	var unmarshaled Resource
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal resource: %v", err)
	}

	if unmarshaled.URI != "file://test.txt" {
		t.Errorf("Expected URI 'file://test.txt', got '%s'", unmarshaled.URI)
	}

	if unmarshaled.MimeType != "text/plain" {
		t.Errorf("Expected mime type 'text/plain', got '%s'", unmarshaled.MimeType)
	}

	if len(unmarshaled.Annotations) != 2 {
		t.Errorf("Expected 2 annotations, got %d", len(unmarshaled.Annotations))
	}
}

func TestPromptSerialization(t *testing.T) {
	prompt := Prompt{
		Name:        "test_prompt",
		Description: "A test prompt",
		Arguments: []PromptArgument{
			{
				Name:        "name",
				Description: "User name",
				Required:    true,
			},
			{
				Name:        "style",
				Description: "Greeting style",
				Required:    false,
			},
		},
	}

	data, err := json.Marshal(prompt)
	if err != nil {
		t.Errorf("Failed to marshal prompt: %v", err)
	}

	var unmarshaled Prompt
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal prompt: %v", err)
	}

	if unmarshaled.Name != "test_prompt" {
		t.Errorf("Expected name 'test_prompt', got '%s'", unmarshaled.Name)
	}

	if len(unmarshaled.Arguments) != 2 {
		t.Errorf("Expected 2 arguments, got %d", len(unmarshaled.Arguments))
	}

	if unmarshaled.Arguments[0].Required != true {
		t.Error("Expected first argument to be required")
	}

	if unmarshaled.Arguments[1].Required != false {
		t.Error("Expected second argument to be optional")
	}
}

func TestServerCapabilitiesSerialization(t *testing.T) {
	caps := ServerCapabilities{
		Tools: &ToolsCapability{
			ListChanged: true,
		},
		Resources: &ResourcesCapability{
			Subscribe:   true,
			ListChanged: false,
		},
		Prompts: &PromptsCapability{
			ListChanged: true,
		},
		Logging: &LoggingCapability{},
	}

	data, err := json.Marshal(caps)
	if err != nil {
		t.Errorf("Failed to marshal capabilities: %v", err)
	}

	var unmarshaled ServerCapabilities
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal capabilities: %v", err)
	}

	if unmarshaled.Tools == nil {
		t.Error("Expected tools capability")
	}

	if unmarshaled.Tools.ListChanged != true {
		t.Error("Expected tools listChanged to be true")
	}

	if unmarshaled.Resources == nil {
		t.Error("Expected resources capability")
	}

	if unmarshaled.Resources.Subscribe != true {
		t.Error("Expected resources subscribe to be true")
	}
}

func TestJSONSchemaSerialization(t *testing.T) {
	schema := JSONSchema{
		Type:        "object",
		Description: "Test schema",
		Properties: map[string]*JSONSchema{
			"stringProp": {
				Type:        "string",
				Description: "A string property",
				MinLength:   &[]int{1}[0],
				MaxLength:   &[]int{100}[0],
				Pattern:     "^[a-zA-Z]+$",
			},
			"numberProp": {
				Type:        "number",
				Description: "A number property",
				Minimum:     &[]float64{0}[0],
				Maximum:     &[]float64{1000}[0],
			},
			"arrayProp": {
				Type:        "array",
				Description: "An array property",
				Items: &JSONSchema{
					Type: "string",
				},
			},
			"enumProp": {
				Type: "string",
				Enum: []interface{}{"option1", "option2", "option3"},
			},
		},
		Required: []string{"stringProp", "numberProp"},
		Examples: []interface{}{
			map[string]interface{}{
				"stringProp": "example",
				"numberProp": 42,
			},
		},
	}

	data, err := json.Marshal(schema)
	if err != nil {
		t.Errorf("Failed to marshal schema: %v", err)
	}

	var unmarshaled JSONSchema
	err = json.Unmarshal(data, &unmarshaled)
	if err != nil {
		t.Errorf("Failed to unmarshal schema: %v", err)
	}

	if unmarshaled.Type != "object" {
		t.Errorf("Expected type 'object', got '%s'", unmarshaled.Type)
	}

	if len(unmarshaled.Properties) != 4 {
		t.Errorf("Expected 4 properties, got %d", len(unmarshaled.Properties))
	}

	if len(unmarshaled.Required) != 2 {
		t.Errorf("Expected 2 required fields, got %d", len(unmarshaled.Required))
	}

	// Test nested properties
	stringProp := unmarshaled.Properties["stringProp"]
	if stringProp.Type != "string" {
		t.Errorf("Expected stringProp type 'string', got '%s'", stringProp.Type)
	}

	if stringProp.Pattern != "^[a-zA-Z]+$" {
		t.Errorf("Expected pattern '^[a-zA-Z]+$', got '%s'", stringProp.Pattern)
	}

	arrayProp := unmarshaled.Properties["arrayProp"]
	if arrayProp.Items == nil {
		t.Error("Expected array items schema")
	}

	if arrayProp.Items.Type != "string" {
		t.Errorf("Expected array items type 'string', got '%s'", arrayProp.Items.Type)
	}

	enumProp := unmarshaled.Properties["enumProp"]
	if len(enumProp.Enum) != 3 {
		t.Errorf("Expected 3 enum values, got %d", len(enumProp.Enum))
	}
}

func TestMethodConstants(t *testing.T) {
	expectedMethods := map[string]string{
		MethodInitialize:     "initialize",
		MethodInitialized:    "initialized",
		MethodToolsList:      "tools/list",
		MethodToolsCall:      "tools/call",
		MethodResourcesList:  "resources/list",
		MethodResourcesRead:  "resources/read",
		MethodPromptsList:    "prompts/list",
		MethodPromptsGet:     "prompts/get",
		MethodLoggingMessage: "notifications/message",
		MethodProgress:       "notifications/progress",
		MethodRootsList:      "roots/list",
		MethodCancelled:      "notifications/cancelled",
	}

	for constant, expected := range expectedMethods {
		if constant != expected {
			t.Errorf("Expected method constant '%s', got '%s'", expected, constant)
		}
	}
}

func TestErrorCodeConstants(t *testing.T) {
	expectedCodes := map[int]int{
		ErrCodeParseError:     -32700,
		ErrCodeInvalidRequest: -32600,
		ErrCodeMethodNotFound: -32601,
		ErrCodeInvalidParams:  -32602,
		ErrCodeInternalError:  -32603,
	}

	for constant, expected := range expectedCodes {
		if constant != expected {
			t.Errorf("Expected error code %d, got %d", expected, constant)
		}
	}
}

func TestLogLevelConstants(t *testing.T) {
	expectedLevels := map[LoggingLevel]string{
		LogLevelDebug:     "debug",
		LogLevelInfo:      "info",
		LogLevelNotice:    "notice",
		LogLevelWarning:   "warning",
		LogLevelError:     "error",
		LogLevelCritical:  "critical",
		LogLevelAlert:     "alert",
		LogLevelEmergency: "emergency",
	}

	for constant, expected := range expectedLevels {
		if string(constant) != expected {
			t.Errorf("Expected log level '%s', got '%s'", expected, string(constant))
		}
	}
}
