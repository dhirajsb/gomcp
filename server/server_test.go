package server

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/dhirajsb/gomcp/types"
)

func TestNewServer(t *testing.T) {
	server := NewServer("test-server", "1.0.0")

	if server.info.Name != "test-server" {
		t.Errorf("Expected server name 'test-server', got '%s'", server.info.Name)
	}

	if server.info.Version != "1.0.0" {
		t.Errorf("Expected server version '1.0.0', got '%s'", server.info.Version)
	}

	if server.tools == nil {
		t.Error("Expected tools map to be initialized")
	}

	if server.resources == nil {
		t.Error("Expected resources map to be initialized")
	}

	if server.prompts == nil {
		t.Error("Expected prompts map to be initialized")
	}
}

func TestRegisterTool(t *testing.T) {
	server := NewServer("test", "1.0")

	// Test function
	addFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}

	err := server.RegisterTool("add", addFunc)
	if err != nil {
		t.Errorf("Failed to register tool: %v", err)
	}

	if len(server.tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(server.tools))
	}

	if _, exists := server.tools["add"]; !exists {
		t.Error("Tool 'add' not found in server.tools")
	}
}

func TestRegisterResource(t *testing.T) {
	server := NewServer("test", "1.0")

	// Test function
	statusFunc := func(ctx context.Context) (string, error) {
		return "running", nil
	}

	err := server.RegisterResource("status", statusFunc)
	if err != nil {
		t.Errorf("Failed to register resource: %v", err)
	}

	if len(server.resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(server.resources))
	}

	if _, exists := server.resources["status"]; !exists {
		t.Error("Resource 'status' not found in server.resources")
	}
}

func TestRegisterPrompt(t *testing.T) {
	server := NewServer("test", "1.0")

	// Test function
	greetFunc := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name, nil
	}

	err := server.RegisterPrompt("greet", greetFunc)
	if err != nil {
		t.Errorf("Failed to register prompt: %v", err)
	}

	if len(server.prompts) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(server.prompts))
	}

	if _, exists := server.prompts["greet"]; !exists {
		t.Error("Prompt 'greet' not found in server.prompts")
	}
}

func TestHandleInitialize(t *testing.T) {
	server := NewServer("test-server", "1.0.0")

	result, err := server.handleInitialize(context.Background(), nil)
	if err != nil {
		t.Errorf("handleInitialize failed: %v", err)
	}

	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("Expected protocol version '2024-11-05', got '%s'", result.ProtocolVersion)
	}

	if result.ServerInfo.Name != "test-server" {
		t.Errorf("Expected server name 'test-server', got '%s'", result.ServerInfo.Name)
	}

	if result.ServerInfo.Version != "1.0.0" {
		t.Errorf("Expected server version '1.0.0', got '%s'", result.ServerInfo.Version)
	}
}

func TestHandleToolsList(t *testing.T) {
	server := NewServer("test", "1.0")

	// Register a test tool
	addFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}
	server.RegisterTool("add", addFunc)

	result, err := server.handleToolsList(context.Background())
	if err != nil {
		t.Errorf("handleToolsList failed: %v", err)
	}

	if len(result.Tools) != 1 {
		t.Errorf("Expected 1 tool, got %d", len(result.Tools))
	}

	tool := result.Tools[0]
	if tool.Name != "add" {
		t.Errorf("Expected tool name 'add', got '%s'", tool.Name)
	}

	if tool.InputSchema.Type != "object" {
		t.Errorf("Expected schema type 'object', got '%s'", tool.InputSchema.Type)
	}
}

func TestHandleToolsCall(t *testing.T) {
	server := NewServer("test", "1.0")

	// Register a test tool
	addFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}
	server.RegisterTool("add", addFunc)

	// Test tool call
	params := types.ToolsCallRequest{
		Name: "add",
		Arguments: map[string]interface{}{
			"param0": 5,
			"param1": 3,
		},
	}

	result, err := server.handleToolsCall(context.Background(), params)
	if err != nil {
		t.Errorf("handleToolsCall failed: %v", err)
	}

	if result.IsError {
		t.Error("Expected successful tool call")
	}

	if len(result.Content) != 1 {
		t.Errorf("Expected 1 content item, got %d", len(result.Content))
	}

	// The result should be "8" as JSON
	if result.Content[0].Text != "8" {
		t.Errorf("Expected result '8', got '%s'", result.Content[0].Text)
	}
}

func TestHandleResourcesList(t *testing.T) {
	server := NewServer("test", "1.0")

	// Register a test resource
	statusFunc := func(ctx context.Context) (string, error) {
		return "running", nil
	}
	server.RegisterResource("status", statusFunc)

	result, err := server.handleResourcesList(context.Background())
	if err != nil {
		t.Errorf("handleResourcesList failed: %v", err)
	}

	if len(result.Resources) != 1 {
		t.Errorf("Expected 1 resource, got %d", len(result.Resources))
	}

	resource := result.Resources[0]
	if resource.Name != "status" {
		t.Errorf("Expected resource name 'status', got '%s'", resource.Name)
	}

	if resource.URI != "resource://status" {
		t.Errorf("Expected URI 'resource://status', got '%s'", resource.URI)
	}
}

func TestHandleResourcesRead(t *testing.T) {
	server := NewServer("test", "1.0")

	// Register a test resource
	statusFunc := func(ctx context.Context) (string, error) {
		return "running", nil
	}
	server.RegisterResource("status", statusFunc)

	// Test resource read
	params := types.ResourcesReadRequest{
		URI: "resource://status",
	}

	result, err := server.handleResourcesRead(context.Background(), params)
	if err != nil {
		t.Errorf("handleResourcesRead failed: %v", err)
	}

	if len(result.Contents) != 1 {
		t.Errorf("Expected 1 content item, got %d", len(result.Contents))
	}

	content := result.Contents[0]
	if content.URI != "resource://status" {
		t.Errorf("Expected URI 'resource://status', got '%s'", content.URI)
	}

	if content.Text != "running" {
		t.Errorf("Expected text 'running', got '%s'", content.Text)
	}
}

func TestHandlePromptsList(t *testing.T) {
	server := NewServer("test", "1.0")

	// Register a test prompt
	greetFunc := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name, nil
	}
	server.RegisterPrompt("greet", greetFunc)

	result, err := server.handlePromptsList(context.Background())
	if err != nil {
		t.Errorf("handlePromptsList failed: %v", err)
	}

	if len(result.Prompts) != 1 {
		t.Errorf("Expected 1 prompt, got %d", len(result.Prompts))
	}

	prompt := result.Prompts[0]
	if prompt.Name != "greet" {
		t.Errorf("Expected prompt name 'greet', got '%s'", prompt.Name)
	}
}

func TestHandlePromptsGet(t *testing.T) {
	server := NewServer("test", "1.0")

	// Register a test prompt
	greetFunc := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name, nil
	}
	server.RegisterPrompt("greet", greetFunc)

	// Test prompt get
	params := types.PromptsGetRequest{
		Name: "greet",
		Arguments: map[string]string{
			"param0": "World",
		},
	}

	result, err := server.handlePromptsGet(context.Background(), params)
	if err != nil {
		t.Errorf("handlePromptsGet failed: %v", err)
	}

	if len(result.Messages) != 1 {
		t.Errorf("Expected 1 message, got %d", len(result.Messages))
	}

	message := result.Messages[0]
	if message.Role != "user" {
		t.Errorf("Expected role 'user', got '%s'", message.Role)
	}

	if message.Content.Text != "Hello World" {
		t.Errorf("Expected text 'Hello World', got '%s'", message.Content.Text)
	}
}

func TestFunctionHandler(t *testing.T) {
	// Test function
	addFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}

	handler, err := NewFunctionHandler("add", addFunc)
	if err != nil {
		t.Errorf("Failed to create function handler: %v", err)
	}

	if handler.Name() != "add" {
		t.Errorf("Expected name 'add', got '%s'", handler.Name())
	}

	schema := handler.Schema()
	if schema.Type != "object" {
		t.Errorf("Expected schema type 'object', got '%s'", schema.Type)
	}

	// Test function call
	params := map[string]interface{}{
		"param0": 5,
		"param1": 3,
	}

	result, err := handler.Call(context.Background(), params)
	if err != nil {
		t.Errorf("Function call failed: %v", err)
	}

	if result != 8 {
		t.Errorf("Expected result 8, got %v", result)
	}
}

func TestGenerateSchemaFromFunction(t *testing.T) {
	// Test function with different parameter types
	testFunc := func(ctx context.Context, str string, num int, flag bool) (string, error) {
		return "", nil
	}

	fnType := reflect.TypeOf(testFunc)
	schema, err := generateSchemaFromFunction(fnType)
	if err != nil {
		t.Errorf("Failed to generate schema: %v", err)
	}

	if schema.Type != "object" {
		t.Errorf("Expected schema type 'object', got '%s'", schema.Type)
	}

	if len(schema.Properties) != 3 { // ctx is skipped
		t.Errorf("Expected 3 properties, got %d", len(schema.Properties))
	}

	// Check string parameter
	if strProp, exists := schema.Properties["param0"]; exists {
		if strProp.Type != "string" {
			t.Errorf("Expected param0 type 'string', got '%s'", strProp.Type)
		}
	} else {
		t.Error("Expected param0 property not found")
	}

	// Check int parameter
	if intProp, exists := schema.Properties["param1"]; exists {
		if intProp.Type != "integer" {
			t.Errorf("Expected param1 type 'integer', got '%s'", intProp.Type)
		}
	} else {
		t.Error("Expected param1 property not found")
	}

	// Check bool parameter
	if boolProp, exists := schema.Properties["param2"]; exists {
		if boolProp.Type != "boolean" {
			t.Errorf("Expected param2 type 'boolean', got '%s'", boolProp.Type)
		}
	} else {
		t.Error("Expected param2 property not found")
	}
}

func TestHandleMessage(t *testing.T) {
	server := NewServer("test", "1.0")

	// Test initialize message
	initReq := types.Request{
		Message: types.Message{
			JSONRPC: "2.0",
			ID:      1,
		},
		Method: types.MethodInitialize,
		Params: types.InitializeParams{
			ProtocolVersion: "2024-11-05",
			Capabilities:    types.ClientCapabilities{},
			ClientInfo: types.ClientInfo{
				Name:    "test-client",
				Version: "1.0.0",
			},
		},
	}

	reqData, _ := json.Marshal(initReq)
	response := server.handleMessage(context.Background(), reqData)

	respData, _ := json.Marshal(response)
	var resp types.Response
	json.Unmarshal(respData, &resp)

	if resp.Error != nil {
		t.Errorf("Expected no error, got: %v", resp.Error)
	}

	// ID might be float64 after JSON unmarshaling
	if respID, ok := resp.ID.(float64); ok {
		if respID != 1.0 {
			t.Errorf("Expected ID 1, got %v", resp.ID)
		}
	} else if resp.ID != 1 {
		t.Errorf("Expected ID 1, got %v", resp.ID)
	}
}

func TestInvalidMessage(t *testing.T) {
	server := NewServer("test", "1.0")

	// Test invalid JSON
	response := server.handleMessage(context.Background(), []byte("invalid json"))

	respData, _ := json.Marshal(response)
	var resp types.Response
	json.Unmarshal(respData, &resp)

	if resp.Error == nil {
		t.Error("Expected parse error for invalid JSON")
	}

	if resp.Error.Code != types.ErrCodeParseError {
		t.Errorf("Expected parse error code %d, got %d", types.ErrCodeParseError, resp.Error.Code)
	}
}

func TestUnknownMethod(t *testing.T) {
	server := NewServer("test", "1.0")

	// Test unknown method
	req := types.Request{
		Message: types.Message{
			JSONRPC: "2.0",
			ID:      1,
		},
		Method: "unknown/method",
	}

	reqData, _ := json.Marshal(req)
	response := server.handleMessage(context.Background(), reqData)

	respData, _ := json.Marshal(response)
	var resp types.Response
	json.Unmarshal(respData, &resp)

	if resp.Error == nil {
		t.Error("Expected method not found error")
	}

	if resp.Error.Code != types.ErrCodeMethodNotFound {
		t.Errorf("Expected method not found error code %d, got %d", types.ErrCodeMethodNotFound, resp.Error.Code)
	}
}
