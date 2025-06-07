package transport

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SSETransport implements MCP over Server-Sent Events
type SSETransport struct {
	config   HTTPConfig
	server   *http.Server
	listener net.Listener
	connCh   chan Connection
	mu       sync.Mutex
	closed   bool
}

// NewSSETransport creates a new SSE transport
func NewSSETransport(config HTTPConfig) *SSETransport {
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.Path == "" {
		config.Path = "/sse"
	}

	return &SSETransport{
		config: config,
		connCh: make(chan Connection, 1),
	}
}

func (t *SSETransport) Listen() error {
	mux := http.NewServeMux()

	// SSE endpoint for client connections
	mux.HandleFunc(t.config.Path, t.handleSSE)

	// Message endpoint for client requests
	mux.HandleFunc(t.config.Path+"/message", t.handleMessage)

	t.server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", t.config.Host, t.config.Port),
		Handler: mux,
	}

	var err error
	t.listener, err = net.Listen("tcp", t.server.Addr)
	if err != nil {
		return err
	}

	go func() {
		if err := t.server.Serve(t.listener); err != nil && err != http.ErrServerClosed {
			fmt.Printf("SSE server error: %v\n", err)
		}
	}()

	return nil
}

func (t *SSETransport) Accept() (Connection, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for SSE connection")
	}
}

func (t *SSETransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}

	t.closed = true
	close(t.connCh)

	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return t.server.Shutdown(ctx)
	}

	return nil
}

func (t *SSETransport) Type() string {
	return TransportSSE
}

func (t *SSETransport) handleSSE(w http.ResponseWriter, r *http.Request) {
	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Create SSE connection
	conn := &SSEConnection{
		writer:   w,
		flusher:  flusher,
		ctx:      r.Context(),
		requests: make(chan []byte, 100),
		done:     make(chan struct{}),
	}

	// Store connection for message handling
	t.storeConnection(r, conn)

	// Send connection to Accept()
	select {
	case t.connCh <- conn:
	default:
		// Channel full, connection will be closed
	}

	// Keep connection alive
	<-conn.done
}

func (t *SSETransport) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get connection for this session
	conn := t.getConnection(r)
	if conn == nil {
		http.Error(w, "No SSE connection found", http.StatusBadRequest)
		return
	}

	// Read request body
	var requestData json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Send to connection for processing
	select {
	case conn.requests <- requestData:
		w.WriteHeader(http.StatusOK)
	default:
		http.Error(w, "Request queue full", http.StatusServiceUnavailable)
	}
}

// Connection storage (simplified - in production use proper session management)
var sseConnections = make(map[string]*SSEConnection)
var sseConnMutex sync.RWMutex

func (t *SSETransport) storeConnection(r *http.Request, conn *SSEConnection) {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.RemoteAddr // Fallback to IP
	}

	sseConnMutex.Lock()
	sseConnections[sessionID] = conn
	sseConnMutex.Unlock()
}

func (t *SSETransport) getConnection(r *http.Request) *SSEConnection {
	sessionID := r.Header.Get("X-Session-ID")
	if sessionID == "" {
		sessionID = r.RemoteAddr
	}

	sseConnMutex.RLock()
	conn := sseConnections[sessionID]
	sseConnMutex.RUnlock()

	return conn
}

// SSEConnection represents an SSE connection
type SSEConnection struct {
	writer   http.ResponseWriter
	flusher  http.Flusher
	ctx      context.Context
	requests chan []byte
	done     chan struct{}
	closed   bool
	mu       sync.Mutex
}

func (c *SSEConnection) Read() ([]byte, error) {
	select {
	case data := <-c.requests:
		return data, nil
	case <-c.ctx.Done():
		return nil, c.ctx.Err()
	case <-c.done:
		return nil, fmt.Errorf("connection closed")
	}
}

func (c *SSEConnection) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection closed")
	}

	// Format as SSE event
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if _, err := fmt.Fprintf(c.writer, "data: %s\n", line); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprint(c.writer, "\n"); err != nil {
		return err
	}

	c.flusher.Flush()
	return nil
}

func (c *SSEConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.closed {
		c.closed = true
		close(c.done)
	}

	return nil
}

func (c *SSEConnection) Context() context.Context {
	return c.ctx
}

func (c *SSEConnection) RemoteAddr() string {
	// Extract from context or use default
	return "sse-client"
}
