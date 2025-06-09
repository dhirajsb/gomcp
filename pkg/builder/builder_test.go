package builder

import (
	"testing"
)

func TestNew(t *testing.T) {
	builder := New("test-server", "1.0.0")

	if builder == nil {
		t.Fatal("Expected builder to be created, got nil")
	}

	if builder.config == nil {
		t.Fatal("Expected config to be initialized, got nil")
	}

	if len(builder.loggers) != 0 {
		t.Errorf("Expected empty loggers slice, got %d items", len(builder.loggers))
	}

	if len(builder.caches) != 0 {
		t.Errorf("Expected empty caches slice, got %d items", len(builder.caches))
	}
}

func TestBuilder_WithLogger(t *testing.T) {
	builder := New("test", "1.0.0")

	logger := ConsoleLogger("test-logger", "info")
	result := builder.WithLogger(logger)

	// Should return the same builder for chaining
	if result != builder {
		t.Error("Expected WithLogger to return the same builder for chaining")
	}

	if len(builder.loggers) != 1 {
		t.Errorf("Expected 1 logger, got %d", len(builder.loggers))
	}

	if builder.loggers[0].Name() != "test-logger" {
		t.Errorf("Expected logger name 'test-logger', got '%s'", builder.loggers[0].Name())
	}
}

func TestBuilder_WithMultipleLoggers(t *testing.T) {
	builder := New("test", "1.0.0")

	logger1 := ConsoleLogger("console", "info")
	logger2 := JSONLogger("json", "debug")
	logger3 := DebugLogger("debug")

	builder.WithLogger(logger1).
		WithLogger(logger2).
		WithLogger(logger3)

	if len(builder.loggers) != 3 {
		t.Errorf("Expected 3 loggers, got %d", len(builder.loggers))
	}

	expectedNames := []string{"console", "json", "debug"}
	for i, expected := range expectedNames {
		if builder.loggers[i].Name() != expected {
			t.Errorf("Expected logger %d name '%s', got '%s'", i, expected, builder.loggers[i].Name())
		}
	}
}

func TestBuilder_WithCache(t *testing.T) {
	builder := New("test", "1.0.0")

	cache := SmallCache("test-cache")
	result := builder.WithCache(cache)

	// Should return the same builder for chaining
	if result != builder {
		t.Error("Expected WithCache to return the same builder for chaining")
	}

	if len(builder.caches) != 1 {
		t.Errorf("Expected 1 cache, got %d", len(builder.caches))
	}

	if builder.caches[0].Name() != "test-cache" {
		t.Errorf("Expected cache name 'test-cache', got '%s'", builder.caches[0].Name())
	}
}

func TestBuilder_WithMultipleCaches(t *testing.T) {
	builder := New("test", "1.0.0")

	cache1 := SmallCache("small")
	cache2 := MediumCache("medium")
	cache3 := LargeCache("large")

	builder.WithCache(cache1).
		WithCache(cache2).
		WithCache(cache3)

	if len(builder.caches) != 3 {
		t.Errorf("Expected 3 caches, got %d", len(builder.caches))
	}

	expectedNames := []string{"small", "medium", "large"}
	for i, expected := range expectedNames {
		if builder.caches[i].Name() != expected {
			t.Errorf("Expected cache %d name '%s', got '%s'", i, expected, builder.caches[i].Name())
		}
	}
}

func TestBuilder_WithAuth(t *testing.T) {
	builder := New("test", "1.0.0")

	auth := JWTAuth("test-auth", "secret123")
	result := builder.WithAuth(auth)

	// Should return the same builder for chaining
	if result != builder {
		t.Error("Expected WithAuth to return the same builder for chaining")
	}

	if len(builder.auths) != 1 {
		t.Errorf("Expected 1 auth, got %d", len(builder.auths))
	}

	if builder.auths[0].Name() != "test-auth" {
		t.Errorf("Expected auth name 'test-auth', got '%s'", builder.auths[0].Name())
	}
}

func TestBuilder_WithSecurity(t *testing.T) {
	builder := New("test", "1.0.0")

	security := StrictValidator("test-security")
	result := builder.WithSecurity(security)

	// Should return the same builder for chaining
	if result != builder {
		t.Error("Expected WithSecurity to return the same builder for chaining")
	}

	if len(builder.securities) != 1 {
		t.Errorf("Expected 1 security validator, got %d", len(builder.securities))
	}

	if builder.securities[0].Name() != "test-security" {
		t.Errorf("Expected security name 'test-security', got '%s'", builder.securities[0].Name())
	}
}

func TestBuilder_WithTelemetry(t *testing.T) {
	builder := New("test", "1.0.0")

	telemetry := StdoutTelemetry("test-telemetry")
	result := builder.WithTelemetry(telemetry)

	// Should return the same builder for chaining
	if result != builder {
		t.Error("Expected WithTelemetry to return the same builder for chaining")
	}

	if len(builder.telemetries) != 1 {
		t.Errorf("Expected 1 telemetry provider, got %d", len(builder.telemetries))
	}

	if builder.telemetries[0].Name() != "test-telemetry" {
		t.Errorf("Expected telemetry name 'test-telemetry', got '%s'", builder.telemetries[0].Name())
	}
}

func TestBuilder_WithMetrics(t *testing.T) {
	builder := New("test", "1.0.0")

	metrics := SimpleMetrics("test-metrics")
	result := builder.WithMetrics(metrics)

	// Should return the same builder for chaining
	if result != builder {
		t.Error("Expected WithMetrics to return the same builder for chaining")
	}

	if len(builder.metrics) != 1 {
		t.Errorf("Expected 1 metrics provider, got %d", len(builder.metrics))
	}

	if builder.metrics[0].Name() != "test-metrics" {
		t.Errorf("Expected metrics name 'test-metrics', got '%s'", builder.metrics[0].Name())
	}
}

func TestBuilder_Build(t *testing.T) {
	builder := New("test-server", "1.0.0").
		WithLogger(ConsoleLogger("console", "info")).
		WithCache(SmallCache("cache")).
		WithTelemetry(StdoutTelemetry("telemetry")).
		WithMetrics(SimpleMetrics("metrics"))

	server, err := builder.Build()

	if err != nil {
		t.Fatalf("Expected no error from Build(), got %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}

	if server.Name() != "test-server" {
		t.Errorf("Expected server name 'test-server', got '%s'", server.Name())
	}

	// Check that features are available
	if len(server.GetLoggers()) != 1 {
		t.Errorf("Expected 1 logger in built server, got %d", len(server.GetLoggers()))
	}

	if len(server.GetCaches()) != 1 {
		t.Errorf("Expected 1 cache in built server, got %d", len(server.GetCaches()))
	}
}

func TestBuilder_BuildEmpty(t *testing.T) {
	builder := New("minimal-server", "1.0.0")

	server, err := builder.Build()

	if err != nil {
		t.Fatalf("Expected no error from Build() with no features, got %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be created even with no features, got nil")
	}

	if server.Name() != "minimal-server" {
		t.Errorf("Expected server name 'minimal-server', got '%s'", server.Name())
	}

	// Should have empty feature lists
	if len(server.GetLoggers()) != 0 {
		t.Errorf("Expected 0 loggers in minimal server, got %d", len(server.GetLoggers()))
	}

	if len(server.GetCaches()) != 0 {
		t.Errorf("Expected 0 caches in minimal server, got %d", len(server.GetCaches()))
	}
}

func TestBuilder_ChainedCalls(t *testing.T) {
	// Test that all builder methods can be chained
	server, err := New("chained-server", "1.0.0").
		WithName("renamed-server").
		WithVersion("2.0.0").
		WithLogger(ConsoleLogger("console", "info")).
		WithLogger(JSONLogger("json", "debug")).
		WithCache(SmallCache("l1")).
		WithCache(MediumCache("l2")).
		WithAuth(JWTAuth("auth", "secret")).
		WithSecurity(StrictValidator("security")).
		WithTelemetry(StdoutTelemetry("telemetry")).
		WithMetrics(SimpleMetrics("metrics")).
		Build()

	if err != nil {
		t.Fatalf("Expected no error from chained build, got %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be created from chained calls, got nil")
	}

	// Verify all features were added
	if len(server.GetLoggers()) != 2 {
		t.Errorf("Expected 2 loggers, got %d", len(server.GetLoggers()))
	}

	if len(server.GetCaches()) != 2 {
		t.Errorf("Expected 2 caches, got %d", len(server.GetCaches()))
	}
}

func TestBuilder_GetConfig(t *testing.T) {
	builder := New("test", "1.0.0")

	config := builder.GetConfig()

	if config == nil {
		t.Fatal("Expected config to be returned, got nil")
	}

	if config.Name != "test" {
		t.Errorf("Expected config name 'test', got '%s'", config.Name)
	}

	if config.Version != "1.0.0" {
		t.Errorf("Expected config version '1.0.0', got '%s'", config.Version)
	}
}

func TestBuilder_GetFeatureSummary(t *testing.T) {
	builder := New("test", "1.0.0").
		WithLogger(ConsoleLogger("console", "info")).
		WithLogger(JSONLogger("json", "debug")).
		WithCache(SmallCache("cache")).
		WithAuth(JWTAuth("auth", "secret")).
		WithMetrics(SimpleMetrics("metrics"))

	summary := builder.GetFeatureSummary()

	if summary == nil {
		t.Fatal("Expected feature summary to be returned, got nil")
	}

	expectedCounts := map[string]int{
		"loggers":     2,
		"caches":      1,
		"auths":       1,
		"securities":  0,
		"telemetries": 0,
		"metrics":     1,
	}

	for feature, expectedCount := range expectedCounts {
		if count, exists := summary[feature]; !exists {
			t.Errorf("Expected feature '%s' to be in summary", feature)
		} else if count != expectedCount {
			t.Errorf("Expected %d %s, got %d", expectedCount, feature, count)
		}
	}
}

func TestBuilder_WithName(t *testing.T) {
	builder := New("original", "1.0.0")

	result := builder.WithName("updated")

	if result != builder {
		t.Error("Expected WithName to return the same builder for chaining")
	}

	config := builder.GetConfig()
	if config.Name != "updated" {
		t.Errorf("Expected updated name 'updated', got '%s'", config.Name)
	}
}

func TestBuilder_WithVersion(t *testing.T) {
	builder := New("test", "1.0.0")

	result := builder.WithVersion("2.0.0")

	if result != builder {
		t.Error("Expected WithVersion to return the same builder for chaining")
	}

	config := builder.GetConfig()
	if config.Version != "2.0.0" {
		t.Errorf("Expected updated version '2.0.0', got '%s'", config.Version)
	}
}

func TestPresetBuilders(t *testing.T) {
	tests := []struct {
		name      string
		builderFn func() *Builder
	}{
		{"Minimal", func() *Builder { return Minimal("test", "1.0.0") }},
		{"Development", func() *Builder { return Development("test", "1.0.0") }},
		{"Production", func() *Builder { return Production("test", "1.0.0") }},
		{"QuickDev", func() *Builder { return QuickDev("test", "1.0.0") }},
		{"QuickProd", func() *Builder { return QuickProd("test", "1.0.0") }},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder := test.builderFn()

			if builder == nil {
				t.Fatalf("Expected %s builder to be created, got nil", test.name)
			}

			server, err := builder.Build()
			if err != nil {
				t.Fatalf("Expected %s builder to build successfully, got error: %v", test.name, err)
			}

			if server == nil {
				t.Fatalf("Expected %s to produce a server, got nil", test.name)
			}

			if server.Name() != "test" {
				t.Errorf("Expected server name 'test', got '%s'", server.Name())
			}

			// Clean up
			server.Close()
		})
	}
}

func TestConfiguredServer_GetMethods(t *testing.T) {
	server, err := New("test", "1.0.0").
		WithLogger(ConsoleLogger("console", "info")).
		WithCache(SmallCache("cache")).
		Build()

	if err != nil {
		t.Fatalf("Failed to build server: %v", err)
	}
	defer server.Close()

	// Test GetLoggers
	loggers := server.GetLoggers()
	if len(loggers) != 1 {
		t.Errorf("Expected 1 logger, got %d", len(loggers))
	}

	if loggers[0].Name() != "console" {
		t.Errorf("Expected logger name 'console', got '%s'", loggers[0].Name())
	}

	// Test GetCaches
	caches := server.GetCaches()
	if len(caches) != 1 {
		t.Errorf("Expected 1 cache, got %d", len(caches))
	}

	if caches[0].Name() != "cache" {
		t.Errorf("Expected cache name 'cache', got '%s'", caches[0].Name())
	}
}

// Mock feature for testing
type MockFeature struct {
	name string
}

func (m *MockFeature) Name() string { return m.name }
func (m *MockFeature) Close() error { return nil }

func TestBuilder_NilFeatures(t *testing.T) {
	builder := New("test", "1.0.0")

	// Test that nil features are handled gracefully
	builder.WithLogger(nil)
	builder.WithCache(nil)

	// Should still be able to build
	server, err := builder.Build()
	if err != nil {
		t.Fatalf("Expected build to succeed even with nil features, got error: %v", err)
	}

	if server == nil {
		t.Fatal("Expected server to be created, got nil")
	}

	server.Close()
}
