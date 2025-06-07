package server

import (
	"sync"
	"sync/atomic"
	"time"
)

// ServerMetrics provides MCP server performance metrics
type ServerMetrics struct {
	// Request counters
	RequestsTotal      int64 `json:"requests_total"`
	RequestsSuccessful int64 `json:"requests_successful"`
	RequestsFailed     int64 `json:"requests_failed"`

	// Method-specific counters
	InitializeRequests    int64 `json:"initialize_requests"`
	ToolsListRequests     int64 `json:"tools_list_requests"`
	ToolsCallRequests     int64 `json:"tools_call_requests"`
	ResourcesListRequests int64 `json:"resources_list_requests"`
	ResourcesReadRequests int64 `json:"resources_read_requests"`
	PromptsListRequests   int64 `json:"prompts_list_requests"`
	PromptsGetRequests    int64 `json:"prompts_get_requests"`

	// Tool invocation metrics
	ToolInvocations  int64 `json:"tool_invocations"`
	ToolErrors       int64 `json:"tool_errors"`
	ToolLatencySum   int64 `json:"tool_latency_sum_ns"`
	ToolLatencyCount int64 `json:"tool_latency_count"`

	// Resource access metrics
	ResourceReads        int64 `json:"resource_reads"`
	ResourceErrors       int64 `json:"resource_errors"`
	ResourceLatencySum   int64 `json:"resource_latency_sum_ns"`
	ResourceLatencyCount int64 `json:"resource_latency_count"`

	// Prompt access metrics
	PromptAccesses     int64 `json:"prompt_accesses"`
	PromptErrors       int64 `json:"prompt_errors"`
	PromptLatencySum   int64 `json:"prompt_latency_sum_ns"`
	PromptLatencyCount int64 `json:"prompt_latency_count"`

	// Message handling performance
	MessageLatencySum   int64 `json:"message_latency_sum_ns"`
	MessageLatencyCount int64 `json:"message_latency_count"`

	// Error tracking
	ErrorCount    int64     `json:"error_count"`
	LastError     string    `json:"last_error"`
	LastErrorTime time.Time `json:"last_error_time"`

	// Connection metrics
	ActiveConnections  int64 `json:"active_connections"`
	TotalConnections   int64 `json:"total_connections"`
	ConnectionsDropped int64 `json:"connections_dropped"`

	// Transport-specific metrics
	StdioConnections int64 `json:"stdio_connections"`
	HTTPConnections  int64 `json:"http_connections"`
	SSEConnections   int64 `json:"sse_connections"`

	// Memory and performance
	ResponseSizeSum   int64 `json:"response_size_sum_bytes"`
	ResponseSizeCount int64 `json:"response_size_count"`
	RequestSizeSum    int64 `json:"request_size_sum_bytes"`
	RequestSizeCount  int64 `json:"request_size_count"`

	// Start time for uptime calculation
	StartTime time.Time `json:"start_time"`

	mu sync.RWMutex
}

// MethodMetrics tracks metrics for individual MCP methods
type MethodMetrics struct {
	Name         string    `json:"name"`
	Requests     int64     `json:"requests"`
	Successes    int64     `json:"successes"`
	Failures     int64     `json:"failures"`
	AvgLatency   float64   `json:"avg_latency_ms"`
	LastRequest  time.Time `json:"last_request"`
	SuccessRate  float64   `json:"success_rate"`
	TotalLatency int64     `json:"total_latency_ns"`
}

// ToolMetrics tracks metrics for individual tools
type ToolMetrics struct {
	Name           string    `json:"name"`
	Invocations    int64     `json:"invocations"`
	Successes      int64     `json:"successes"`
	Failures       int64     `json:"failures"`
	AvgLatency     float64   `json:"avg_latency_ms"`
	LastInvocation time.Time `json:"last_invocation"`
	SuccessRate    float64   `json:"success_rate"`
}

// NewServerMetrics creates a new server metrics instance
func NewServerMetrics() *ServerMetrics {
	return &ServerMetrics{
		StartTime: time.Now(),
	}
}

// RecordRequest records a request
func (m *ServerMetrics) RecordRequest(method string, success bool, latency time.Duration) {
	atomic.AddInt64(&m.RequestsTotal, 1)

	if success {
		atomic.AddInt64(&m.RequestsSuccessful, 1)
	} else {
		atomic.AddInt64(&m.RequestsFailed, 1)
	}

	// Record message latency
	atomic.AddInt64(&m.MessageLatencySum, int64(latency))
	atomic.AddInt64(&m.MessageLatencyCount, 1)

	// Record method-specific metrics
	switch method {
	case "initialize":
		atomic.AddInt64(&m.InitializeRequests, 1)
	case "tools/list":
		atomic.AddInt64(&m.ToolsListRequests, 1)
	case "tools/call":
		atomic.AddInt64(&m.ToolsCallRequests, 1)
	case "resources/list":
		atomic.AddInt64(&m.ResourcesListRequests, 1)
	case "resources/read":
		atomic.AddInt64(&m.ResourcesReadRequests, 1)
	case "prompts/list":
		atomic.AddInt64(&m.PromptsListRequests, 1)
	case "prompts/get":
		atomic.AddInt64(&m.PromptsGetRequests, 1)
	}
}

// RecordToolInvocation records a tool invocation
func (m *ServerMetrics) RecordToolInvocation(toolName string, success bool, latency time.Duration) {
	atomic.AddInt64(&m.ToolInvocations, 1)

	if !success {
		atomic.AddInt64(&m.ToolErrors, 1)
	}

	atomic.AddInt64(&m.ToolLatencySum, int64(latency))
	atomic.AddInt64(&m.ToolLatencyCount, 1)
}

// RecordResourceRead records a resource read
func (m *ServerMetrics) RecordResourceRead(resourceURI string, success bool, latency time.Duration) {
	atomic.AddInt64(&m.ResourceReads, 1)

	if !success {
		atomic.AddInt64(&m.ResourceErrors, 1)
	}

	atomic.AddInt64(&m.ResourceLatencySum, int64(latency))
	atomic.AddInt64(&m.ResourceLatencyCount, 1)
}

// RecordPromptAccess records a prompt access
func (m *ServerMetrics) RecordPromptAccess(promptName string, success bool, latency time.Duration) {
	atomic.AddInt64(&m.PromptAccesses, 1)

	if !success {
		atomic.AddInt64(&m.PromptErrors, 1)
	}

	atomic.AddInt64(&m.PromptLatencySum, int64(latency))
	atomic.AddInt64(&m.PromptLatencyCount, 1)
}

// RecordError records an error
func (m *ServerMetrics) RecordError(err error) {
	atomic.AddInt64(&m.ErrorCount, 1)

	m.mu.Lock()
	m.LastError = err.Error()
	m.LastErrorTime = time.Now()
	m.mu.Unlock()
}

// RecordConnection records connection events
func (m *ServerMetrics) RecordConnection(transport string, connected bool) {
	if connected {
		atomic.AddInt64(&m.ActiveConnections, 1)
		atomic.AddInt64(&m.TotalConnections, 1)

		switch transport {
		case "stdio":
			atomic.AddInt64(&m.StdioConnections, 1)
		case "http":
			atomic.AddInt64(&m.HTTPConnections, 1)
		case "sse":
			atomic.AddInt64(&m.SSEConnections, 1)
		}
	} else {
		atomic.AddInt64(&m.ActiveConnections, -1)
	}
}

// RecordConnectionDropped records a dropped connection
func (m *ServerMetrics) RecordConnectionDropped() {
	atomic.AddInt64(&m.ConnectionsDropped, 1)
	atomic.AddInt64(&m.ActiveConnections, -1)
}

// RecordMessageSize records message size metrics
func (m *ServerMetrics) RecordRequestSize(size int64) {
	atomic.AddInt64(&m.RequestSizeSum, size)
	atomic.AddInt64(&m.RequestSizeCount, 1)
}

// RecordResponseSize records response size metrics
func (m *ServerMetrics) RecordResponseSize(size int64) {
	atomic.AddInt64(&m.ResponseSizeSum, size)
	atomic.AddInt64(&m.ResponseSizeCount, 1)
}

// GetStats returns current server statistics
func (m *ServerMetrics) GetStats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	requestsTotal := atomic.LoadInt64(&m.RequestsTotal)
	requestsSuccessful := atomic.LoadInt64(&m.RequestsSuccessful)
	requestsFailed := atomic.LoadInt64(&m.RequestsFailed)

	// Calculate rates
	var successRate float64
	if requestsTotal > 0 {
		successRate = float64(requestsSuccessful) / float64(requestsTotal)
	}

	// Calculate average latencies
	var avgMessageLatency, avgToolLatency, avgResourceLatency, avgPromptLatency float64

	if count := atomic.LoadInt64(&m.MessageLatencyCount); count > 0 {
		avgMessageLatency = float64(atomic.LoadInt64(&m.MessageLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.ToolLatencyCount); count > 0 {
		avgToolLatency = float64(atomic.LoadInt64(&m.ToolLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.ResourceLatencyCount); count > 0 {
		avgResourceLatency = float64(atomic.LoadInt64(&m.ResourceLatencySum)) / float64(count) / 1000000.0
	}
	if count := atomic.LoadInt64(&m.PromptLatencyCount); count > 0 {
		avgPromptLatency = float64(atomic.LoadInt64(&m.PromptLatencySum)) / float64(count) / 1000000.0
	}

	// Calculate average message sizes
	var avgRequestSize, avgResponseSize float64
	if count := atomic.LoadInt64(&m.RequestSizeCount); count > 0 {
		avgRequestSize = float64(atomic.LoadInt64(&m.RequestSizeSum)) / float64(count)
	}
	if count := atomic.LoadInt64(&m.ResponseSizeCount); count > 0 {
		avgResponseSize = float64(atomic.LoadInt64(&m.ResponseSizeSum)) / float64(count)
	}

	// Calculate error rates
	var toolErrorRate, resourceErrorRate, promptErrorRate float64
	if invocations := atomic.LoadInt64(&m.ToolInvocations); invocations > 0 {
		toolErrorRate = float64(atomic.LoadInt64(&m.ToolErrors)) / float64(invocations)
	}
	if reads := atomic.LoadInt64(&m.ResourceReads); reads > 0 {
		resourceErrorRate = float64(atomic.LoadInt64(&m.ResourceErrors)) / float64(reads)
	}
	if accesses := atomic.LoadInt64(&m.PromptAccesses); accesses > 0 {
		promptErrorRate = float64(atomic.LoadInt64(&m.PromptErrors)) / float64(accesses)
	}

	return map[string]interface{}{
		"requests_total":          requestsTotal,
		"requests_successful":     requestsSuccessful,
		"requests_failed":         requestsFailed,
		"success_rate":            successRate,
		"initialize_requests":     atomic.LoadInt64(&m.InitializeRequests),
		"tools_list_requests":     atomic.LoadInt64(&m.ToolsListRequests),
		"tools_call_requests":     atomic.LoadInt64(&m.ToolsCallRequests),
		"resources_list_requests": atomic.LoadInt64(&m.ResourcesListRequests),
		"resources_read_requests": atomic.LoadInt64(&m.ResourcesReadRequests),
		"prompts_list_requests":   atomic.LoadInt64(&m.PromptsListRequests),
		"prompts_get_requests":    atomic.LoadInt64(&m.PromptsGetRequests),
		"tool_invocations":        atomic.LoadInt64(&m.ToolInvocations),
		"tool_errors":             atomic.LoadInt64(&m.ToolErrors),
		"tool_error_rate":         toolErrorRate,
		"resource_reads":          atomic.LoadInt64(&m.ResourceReads),
		"resource_errors":         atomic.LoadInt64(&m.ResourceErrors),
		"resource_error_rate":     resourceErrorRate,
		"prompt_accesses":         atomic.LoadInt64(&m.PromptAccesses),
		"prompt_errors":           atomic.LoadInt64(&m.PromptErrors),
		"prompt_error_rate":       promptErrorRate,
		"avg_message_latency_ms":  avgMessageLatency,
		"avg_tool_latency_ms":     avgToolLatency,
		"avg_resource_latency_ms": avgResourceLatency,
		"avg_prompt_latency_ms":   avgPromptLatency,
		"error_count":             atomic.LoadInt64(&m.ErrorCount),
		"last_error":              m.LastError,
		"last_error_time":         m.LastErrorTime,
		"active_connections":      atomic.LoadInt64(&m.ActiveConnections),
		"total_connections":       atomic.LoadInt64(&m.TotalConnections),
		"connections_dropped":     atomic.LoadInt64(&m.ConnectionsDropped),
		"stdio_connections":       atomic.LoadInt64(&m.StdioConnections),
		"http_connections":        atomic.LoadInt64(&m.HTTPConnections),
		"sse_connections":         atomic.LoadInt64(&m.SSEConnections),
		"avg_request_size_bytes":  avgRequestSize,
		"avg_response_size_bytes": avgResponseSize,
		"uptime":                  time.Since(m.StartTime),
	}
}

// GetMethodStats returns method-specific statistics
func (m *ServerMetrics) GetMethodStats() map[string]*MethodMetrics {
	stats := make(map[string]*MethodMetrics)

	methods := []struct {
		name    string
		counter *int64
	}{
		{"initialize", &m.InitializeRequests},
		{"tools/list", &m.ToolsListRequests},
		{"tools/call", &m.ToolsCallRequests},
		{"resources/list", &m.ResourcesListRequests},
		{"resources/read", &m.ResourcesReadRequests},
		{"prompts/list", &m.PromptsListRequests},
		{"prompts/get", &m.PromptsGetRequests},
	}

	for _, method := range methods {
		requests := atomic.LoadInt64(method.counter)
		if requests > 0 {
			stats[method.name] = &MethodMetrics{
				Name:     method.name,
				Requests: requests,
				// Note: Individual method success/failure tracking would require
				// more detailed instrumentation in the actual request handlers
			}
		}
	}

	return stats
}

// GetConnectionStats returns connection statistics by transport
func (m *ServerMetrics) GetConnectionStats() map[string]interface{} {
	return map[string]interface{}{
		"active":  atomic.LoadInt64(&m.ActiveConnections),
		"total":   atomic.LoadInt64(&m.TotalConnections),
		"dropped": atomic.LoadInt64(&m.ConnectionsDropped),
		"by_transport": map[string]int64{
			"stdio": atomic.LoadInt64(&m.StdioConnections),
			"http":  atomic.LoadInt64(&m.HTTPConnections),
			"sse":   atomic.LoadInt64(&m.SSEConnections),
		},
	}
}
