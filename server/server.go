package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"reflect"
	"runtime"
	"strings"
	"sync"

	"github.com/dhirajsb/gomcp/transport"
	"github.com/dhirajsb/gomcp/types"
	"github.com/go-playground/validator/v10"
)

// Handler interface for all MCP handlers
type Handler interface {
	Call(ctx context.Context, params map[string]interface{}) (interface{}, error)
	Schema() *types.JSONSchema
	Name() string
	Description() string
}

// Server represents an MCP server
type Server struct {
	info      types.ServerInfo
	caps      types.ServerCapabilities
	tools     map[string]Handler
	resources map[string]Handler
	prompts   map[string]Handler
	validator *validator.Validate
	mu        sync.RWMutex
}

// NewServer creates a new MCP server
func NewServer(name, version string) *Server {
	return &Server{
		info: types.ServerInfo{
			Name:    name,
			Version: version,
		},
		caps: types.ServerCapabilities{
			Tools: &types.ToolsCapability{
				ListChanged: false,
			},
			Resources: &types.ResourcesCapability{
				Subscribe:   false,
				ListChanged: false,
			},
			Prompts: &types.PromptsCapability{
				ListChanged: false,
			},
			Logging: &types.LoggingCapability{},
		},
		tools:     make(map[string]Handler),
		resources: make(map[string]Handler),
		prompts:   make(map[string]Handler),
		validator: validator.New(),
	}
}

// RegisterTool registers a function as a tool
func (s *Server) RegisterTool(name string, fn interface{}) error {
	handler, err := NewFunctionHandler(name, fn)
	if err != nil {
		return fmt.Errorf("failed to create tool handler: %w", err)
	}

	s.mu.Lock()
	s.tools[name] = handler
	s.mu.Unlock()

	return nil
}

// RegisterResource registers a function as a resource
func (s *Server) RegisterResource(name string, fn interface{}) error {
	handler, err := NewFunctionHandler(name, fn)
	if err != nil {
		return fmt.Errorf("failed to create resource handler: %w", err)
	}

	s.mu.Lock()
	s.resources[name] = handler
	s.mu.Unlock()

	return nil
}

// RegisterPrompt registers a function as a prompt
func (s *Server) RegisterPrompt(name string, fn interface{}) error {
	handler, err := NewFunctionHandler(name, fn)
	if err != nil {
		return fmt.Errorf("failed to create prompt handler: %w", err)
	}

	s.mu.Lock()
	s.prompts[name] = handler
	s.mu.Unlock()

	return nil
}

// Start starts the server with the given transport
func (s *Server) Start(transport transport.Transport) error {
	if err := transport.Listen(); err != nil {
		return fmt.Errorf("failed to start transport: %w", err)
	}

	log.Printf("MCP Server %s v%s started on %s transport",
		s.info.Name, s.info.Version, transport.Type())

	for {
		conn, err := transport.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn transport.Connection) {
	defer conn.Close()

	log.Printf("New connection from %s", conn.RemoteAddr())

	for {
		data, err := conn.Read()
		if err != nil {
			if err.Error() != "EOF" {
				log.Printf("Read error: %v", err)
			}
			break
		}

		response := s.handleMessage(conn.Context(), data)
		if response != nil {
			responseData, err := json.Marshal(response)
			if err != nil {
				log.Printf("Failed to marshal response: %v", err)
				continue
			}

			if err := conn.Write(responseData); err != nil {
				log.Printf("Write error: %v", err)
				break
			}
		}
	}
}

func (s *Server) handleMessage(ctx context.Context, data []byte) interface{} {
	var req types.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return &types.Response{
			Message: types.Message{
				JSONRPC: "2.0",
				ID:      nil,
			},
			Error: &types.RPCError{
				Code:    types.ErrCodeParseError,
				Message: "Parse error",
			},
		}
	}

	response := &types.Response{
		Message: types.Message{
			JSONRPC: "2.0",
			ID:      req.ID,
		},
	}

	switch req.Method {
	case types.MethodInitialize:
		result, err := s.handleInitialize(ctx, req.Params)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	case types.MethodToolsList:
		result, err := s.handleToolsList(ctx)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	case types.MethodToolsCall:
		result, err := s.handleToolsCall(ctx, req.Params)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	case types.MethodResourcesList:
		result, err := s.handleResourcesList(ctx)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	case types.MethodResourcesRead:
		result, err := s.handleResourcesRead(ctx, req.Params)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	case types.MethodPromptsList:
		result, err := s.handlePromptsList(ctx)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	case types.MethodPromptsGet:
		result, err := s.handlePromptsGet(ctx, req.Params)
		if err != nil {
			response.Error = &types.RPCError{
				Code:    types.ErrCodeInternalError,
				Message: err.Error(),
			}
		} else {
			response.Result = result
		}

	default:
		response.Error = &types.RPCError{
			Code:    types.ErrCodeMethodNotFound,
			Message: fmt.Sprintf("Method not found: %s", req.Method),
		}
	}

	return response
}

func (s *Server) handleInitialize(ctx context.Context, params interface{}) (*types.InitializeResult, error) {
	return &types.InitializeResult{
		ProtocolVersion: "2024-11-05",
		Capabilities:    s.caps,
		ServerInfo:      s.info,
	}, nil
}

func (s *Server) handleToolsList(ctx context.Context) (*types.ToolsListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	tools := make([]types.Tool, 0, len(s.tools))
	for name, handler := range s.tools {
		tools = append(tools, types.Tool{
			Name:        name,
			Description: handler.Description(),
			InputSchema: *handler.Schema(),
		})
	}

	return &types.ToolsListResult{Tools: tools}, nil
}

func (s *Server) handleToolsCall(ctx context.Context, params interface{}) (*types.ToolsCallResult, error) {
	var req types.ToolsCallRequest
	if err := s.unmarshalParams(params, &req); err != nil {
		return nil, err
	}

	s.mu.RLock()
	handler, exists := s.tools[req.Name]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("tool not found: %s", req.Name)
	}

	result, err := handler.Call(ctx, req.Arguments)
	if err != nil {
		return &types.ToolsCallResult{
			IsError: true,
			Content: []types.ContentItem{{
				Type: "text",
				Text: err.Error(),
			}},
		}, nil
	}

	// Convert result to content
	content := s.resultToContent(result)

	return &types.ToolsCallResult{
		Content: content,
		IsError: false,
	}, nil
}

func (s *Server) handleResourcesList(ctx context.Context) (*types.ResourcesListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	resources := make([]types.Resource, 0, len(s.resources))
	for name, handler := range s.resources {
		resources = append(resources, types.Resource{
			URI:         fmt.Sprintf("resource://%s", name),
			Name:        name,
			Description: handler.Description(),
		})
	}

	return &types.ResourcesListResult{Resources: resources}, nil
}

func (s *Server) handleResourcesRead(ctx context.Context, params interface{}) (*types.ResourcesReadResult, error) {
	var req types.ResourcesReadRequest
	if err := s.unmarshalParams(params, &req); err != nil {
		return nil, err
	}

	// Extract resource name from URI
	name := strings.TrimPrefix(req.URI, "resource://")

	s.mu.RLock()
	handler, exists := s.resources[name]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("resource not found: %s", name)
	}

	result, err := handler.Call(ctx, nil)
	if err != nil {
		return nil, err
	}

	content := types.ResourceContent{
		URI:      req.URI,
		MimeType: "text/plain",
	}

	if str, ok := result.(string); ok {
		content.Text = str
	} else {
		data, _ := json.Marshal(result)
		content.Text = string(data)
		content.MimeType = "application/json"
	}

	return &types.ResourcesReadResult{
		Contents: []types.ResourceContent{content},
	}, nil
}

func (s *Server) handlePromptsList(ctx context.Context) (*types.PromptsListResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	prompts := make([]types.Prompt, 0, len(s.prompts))
	for name, handler := range s.prompts {
		prompts = append(prompts, types.Prompt{
			Name:        name,
			Description: handler.Description(),
		})
	}

	return &types.PromptsListResult{Prompts: prompts}, nil
}

func (s *Server) handlePromptsGet(ctx context.Context, params interface{}) (*types.PromptsGetResult, error) {
	var req types.PromptsGetRequest
	if err := s.unmarshalParams(params, &req); err != nil {
		return nil, err
	}

	s.mu.RLock()
	handler, exists := s.prompts[req.Name]
	s.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("prompt not found: %s", req.Name)
	}

	// Convert string arguments to interface{} map
	args := make(map[string]interface{})
	for k, v := range req.Arguments {
		args[k] = v
	}

	result, err := handler.Call(ctx, args)
	if err != nil {
		return nil, err
	}

	// Handle different result types
	if str, ok := result.(string); ok {
		return &types.PromptsGetResult{
			Messages: []types.PromptMessage{{
				Role: "user",
				Content: types.ContentItem{
					Type: "text",
					Text: str,
				},
			}},
		}, nil
	}

	// Handle structured prompt results
	data, _ := json.Marshal(result)
	return &types.PromptsGetResult{
		Messages: []types.PromptMessage{{
			Role: "user",
			Content: types.ContentItem{
				Type: "text",
				Text: string(data),
			},
		}},
	}, nil
}

func (s *Server) unmarshalParams(params interface{}, target interface{}) error {
	data, err := json.Marshal(params)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

func (s *Server) resultToContent(result interface{}) []types.ContentItem {
	if str, ok := result.(string); ok {
		return []types.ContentItem{{
			Type: "text",
			Text: str,
		}}
	}

	if content, ok := result.([]types.ContentItem); ok {
		return content
	}

	// Convert to JSON
	data, _ := json.Marshal(result)
	return []types.ContentItem{{
		Type: "text",
		Text: string(data),
	}}
}

// FunctionHandler wraps a Go function as an MCP handler
type FunctionHandler struct {
	name        string
	description string
	fn          reflect.Value
	fnType      reflect.Type
	schema      *types.JSONSchema
	validator   *validator.Validate
}

// NewFunctionHandler creates a new function handler
func NewFunctionHandler(name string, fn interface{}) (*FunctionHandler, error) {
	fnValue := reflect.ValueOf(fn)
	fnType := fnValue.Type()

	if fnType.Kind() != reflect.Func {
		return nil, fmt.Errorf("expected function, got %v", fnType.Kind())
	}

	// Generate schema from function signature
	schema, err := generateSchemaFromFunction(fnType)
	if err != nil {
		return nil, err
	}

	// Extract description from function name/docs (simplified)
	description := getFunctionDescription(fn)

	return &FunctionHandler{
		name:        name,
		description: description,
		fn:          fnValue,
		fnType:      fnType,
		schema:      schema,
		validator:   nil,
	}, nil
}

func (fh *FunctionHandler) Name() string              { return fh.name }
func (fh *FunctionHandler) Description() string       { return fh.description }
func (fh *FunctionHandler) Schema() *types.JSONSchema { return fh.schema }

func (fh *FunctionHandler) Call(ctx context.Context, params map[string]interface{}) (interface{}, error) {
	args := make([]reflect.Value, 0)

	// Add context if function expects it
	if fh.fnType.NumIn() > 0 && fh.fnType.In(0) == reflect.TypeOf((*context.Context)(nil)).Elem() {
		args = append(args, reflect.ValueOf(ctx))
	}

	// Convert and validate parameters
	paramIndex := 0
	for i := len(args); i < fh.fnType.NumIn(); i++ {
		paramType := fh.fnType.In(i)
		paramName := fmt.Sprintf("param%d", paramIndex)

		var paramValue reflect.Value
		if params != nil && len(params) > 0 {
			if val, exists := params[paramName]; exists {
				convertedVal, err := convertValue(val, paramType)
				if err != nil {
					return nil, fmt.Errorf("invalid parameter %s: %w", paramName, err)
				}
				paramValue = convertedVal
			} else {
				// Use zero value
				paramValue = reflect.Zero(paramType)
			}
		} else {
			paramValue = reflect.Zero(paramType)
		}

		args = append(args, paramValue)
		paramIndex++
	}

	// Call function
	results := fh.fn.Call(args)

	// Handle results
	if len(results) == 0 {
		return nil, nil
	}

	// Check for error (usually last return value)
	if len(results) > 1 {
		if errVal := results[len(results)-1]; !errVal.IsNil() {
			if err, ok := errVal.Interface().(error); ok {
				return nil, err
			}
		}
	}

	// Return first result
	return results[0].Interface(), nil
}

func generateSchemaFromFunction(fnType reflect.Type) (*types.JSONSchema, error) {
	schema := &types.JSONSchema{
		Type:       "object",
		Properties: make(map[string]*types.JSONSchema),
		Required:   []string{},
	}

	startIdx := 0
	// Skip context parameter
	if fnType.NumIn() > 0 && fnType.In(0) == reflect.TypeOf((*context.Context)(nil)).Elem() {
		startIdx = 1
	}

	for i := startIdx; i < fnType.NumIn(); i++ {
		paramType := fnType.In(i)
		paramName := fmt.Sprintf("param%d", i-startIdx)

		propSchema := &types.JSONSchema{}
		setSchemaType(propSchema, paramType)

		schema.Properties[paramName] = propSchema
		schema.Required = append(schema.Required, paramName)
	}

	return schema, nil
}

func setSchemaType(schema *types.JSONSchema, t reflect.Type) {
	switch t.Kind() {
	case reflect.String:
		schema.Type = "string"
	case reflect.Int, reflect.Int32, reflect.Int64:
		schema.Type = "integer"
	case reflect.Float32, reflect.Float64:
		schema.Type = "number"
	case reflect.Bool:
		schema.Type = "boolean"
	case reflect.Slice, reflect.Array:
		schema.Type = "array"
		schema.Items = &types.JSONSchema{}
		setSchemaType(schema.Items, t.Elem())
	case reflect.Struct:
		schema.Type = "object"
		// TODO: Handle struct fields
	default:
		schema.Type = "object"
	}
}

func convertValue(val interface{}, targetType reflect.Type) (reflect.Value, error) {
	if val == nil {
		return reflect.Zero(targetType), nil
	}

	valType := reflect.TypeOf(val)
	if valType.AssignableTo(targetType) {
		return reflect.ValueOf(val), nil
	}

	// Try type conversion
	if valType.ConvertibleTo(targetType) {
		return reflect.ValueOf(val).Convert(targetType), nil
	}

	return reflect.Zero(targetType), fmt.Errorf("cannot convert %v to %v", valType, targetType)
}

func getFunctionDescription(fn interface{}) string {
	fnValue := reflect.ValueOf(fn)
	fnPtr := fnValue.Pointer()
	runtimeFunc := runtime.FuncForPC(fnPtr)
	name := runtimeFunc.Name()

	// Extract function name (simplified)
	parts := strings.Split(name, ".")
	if len(parts) > 0 {
		return fmt.Sprintf("Function %s", parts[len(parts)-1])
	}

	return "Go function"
}
