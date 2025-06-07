package gomcp

import (
	"context"
	"testing"

	"github.com/dhirajsb/gomcp/transport"
)

func TestNewServer(t *testing.T) {
	server := NewServer()

	if server == nil {
		t.Error("Expected non-nil server")
	}

	// Server should have default name and version
	// (We can't easily test this without exposing internal fields,
	// but we can test that it doesn't panic)
}

func TestTransportConstructors(t *testing.T) {
	// Test Stdio constructor
	stdio := Stdio()
	if stdio == nil {
		t.Error("Expected non-nil stdio transport")
	}

	if stdio.Type() != transport.TransportStdio {
		t.Errorf("Expected stdio transport type, got %s", stdio.Type())
	}

	// Test SSE constructor
	sse := SSE("localhost", 8080)
	if sse == nil {
		t.Error("Expected non-nil SSE transport")
	}

	if sse.Type() != transport.TransportSSE {
		t.Errorf("Expected SSE transport type, got %s", sse.Type())
	}

	// Test StreamableHTTP constructor
	http := StreamableHTTP("localhost", 8080)
	if http == nil {
		t.Error("Expected non-nil HTTP transport")
	}

	if http.Type() != transport.TransportStreamableHTTP {
		t.Errorf("Expected HTTP transport type, got %s", http.Type())
	}
}

func TestQuickBuilder(t *testing.T) {
	// Test Quick constructor
	builder := Quick()
	if builder == nil {
		t.Error("Expected non-nil quick builder")
	}

	if builder.server == nil {
		t.Error("Expected non-nil server in builder")
	}

	// Test method chaining
	testFunc := func(ctx context.Context, msg string) (string, error) {
		return "Hello " + msg, nil
	}

	testResource := func(ctx context.Context) (string, error) {
		return "resource data", nil
	}

	testPrompt := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name, nil
	}

	// Test that methods can be chained
	builder2 := builder.
		Tool("test_tool", testFunc).
		Resource("test_resource", testResource).
		Prompt("test_prompt", testPrompt)

	if builder2 != builder {
		t.Error("Expected method chaining to return same builder")
	}

	// We can't easily test Run() without it blocking, but we can test
	// that the methods don't panic and return the expected builder
}

func TestQuickBuilderToolRegistration(t *testing.T) {
	builder := Quick()

	testFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}

	// Test tool registration
	result := builder.Tool("add", testFunc)
	if result != builder {
		t.Error("Expected Tool method to return same builder")
	}

	// Check that the tool was registered (indirect test)
	// We can't easily access the internal server state, but we can
	// verify the method doesn't panic and returns correctly
}

func TestQuickBuilderResourceRegistration(t *testing.T) {
	builder := Quick()

	testFunc := func(ctx context.Context) (string, error) {
		return "test data", nil
	}

	// Test resource registration
	result := builder.Resource("test", testFunc)
	if result != builder {
		t.Error("Expected Resource method to return same builder")
	}
}

func TestQuickBuilderPromptRegistration(t *testing.T) {
	builder := Quick()

	testFunc := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name, nil
	}

	// Test prompt registration
	result := builder.Prompt("greet", testFunc)
	if result != builder {
		t.Error("Expected Prompt method to return same builder")
	}
}

func TestQuickBuilderMethodChaining(t *testing.T) {
	addFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}

	statusFunc := func(ctx context.Context) (string, error) {
		return "running", nil
	}

	greetFunc := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name, nil
	}

	// Test full method chaining
	builder := Quick().
		Tool("add", addFunc).
		Tool("multiply", func(ctx context.Context, a, b int) (int, error) {
			return a * b, nil
		}).
		Resource("status", statusFunc).
		Resource("info", func(ctx context.Context) (map[string]interface{}, error) {
			return map[string]interface{}{
				"name":    "test",
				"version": "1.0",
			}, nil
		}).
		Prompt("greet", greetFunc).
		Prompt("farewell", func(ctx context.Context, name string) (string, error) {
			return "Goodbye " + name, nil
		})

	if builder == nil {
		t.Error("Expected non-nil builder after chaining")
	}

	if builder.server == nil {
		t.Error("Expected non-nil server after chaining")
	}
}

// Integration test (without actually running the server)
func TestQuickAPIIntegration(t *testing.T) {
	// This test verifies that the Quick API works end-to-end
	// without actually starting a server

	addFunc := func(ctx context.Context, a, b int) (int, error) {
		return a + b, nil
	}

	statusFunc := func(ctx context.Context) (string, error) {
		return "running", nil
	}

	greetFunc := func(ctx context.Context, name string) (string, error) {
		return "Hello " + name + "!", nil
	}

	// Build a complete server configuration
	builder := Quick().
		Tool("add", addFunc).
		Resource("status", statusFunc).
		Prompt("greet", greetFunc)

	// Verify builder state
	if builder == nil {
		t.Error("Expected non-nil builder")
	}

	if builder.server == nil {
		t.Error("Expected non-nil server in builder")
	}

	// Note: We don't call Run() here because it would block the test
	// In a real scenario, you would call:
	// log.Fatal(builder.Run())
	// or
	// log.Fatal(builder.RunHTTP("localhost", 8080))
}
