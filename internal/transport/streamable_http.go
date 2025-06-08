package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// StreamableHTTPTransport implements MCP over Streamable HTTP
type StreamableHTTPTransport struct {
	config   HTTPConfig
	server   *http.Server
	listener net.Listener
	connCh   chan Connection
	mu       sync.Mutex
	closed   bool
}

// NewStreamableHTTPTransport creates a new Streamable HTTP transport
func NewStreamableHTTPTransport(config HTTPConfig) *StreamableHTTPTransport {
	if config.Host == "" {
		config.Host = "localhost"
	}
	if config.Port == 0 {
		config.Port = 8080
	}
	if config.Path == "" {
		config.Path = "/mcp"
	}

	return &StreamableHTTPTransport{
		config: config,
		connCh: make(chan Connection, 10),
	}
}

func (t *StreamableHTTPTransport) Listen() error {
	mux := http.NewServeMux()

	// Single endpoint for streamable HTTP
	mux.HandleFunc(t.config.Path, t.handleStreamableHTTP)

	// CORS preflight
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	})

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
			fmt.Printf("Streamable HTTP server error: %v\n", err)
		}
	}()

	return nil
}

func (t *StreamableHTTPTransport) Accept() (Connection, error) {
	select {
	case conn := <-t.connCh:
		return conn, nil
	case <-time.After(30 * time.Second):
		return nil, fmt.Errorf("timeout waiting for HTTP connection")
	}
}

func (t *StreamableHTTPTransport) Close() error {
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

func (t *StreamableHTTPTransport) Type() string {
	return TransportStreamableHTTP
}

func (t *StreamableHTTPTransport) handleStreamableHTTP(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if this is a streaming request
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "text/plain") {
		// Streaming mode
		t.handleStreamingRequest(w, r)
	} else {
		// Single request mode
		t.handleSingleRequest(w, r)
	}
}

func (t *StreamableHTTPTransport) handleStreamingRequest(w http.ResponseWriter, r *http.Request) {
	// Set streaming headers
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Transfer-Encoding", "chunked")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Create streaming connection
	conn := &StreamableHTTPConnection{
		reader:   bufio.NewReader(r.Body),
		writer:   w,
		flusher:  flusher,
		ctx:      r.Context(),
		isStream: true,
	}

	// Send connection to Accept()
	select {
	case t.connCh <- conn:
		// Connection accepted, keep processing
		<-conn.ctx.Done()
	default:
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
	}
}

func (t *StreamableHTTPTransport) handleSingleRequest(w http.ResponseWriter, r *http.Request) {
	// Read entire request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request", http.StatusBadRequest)
		return
	}

	// Create single-request connection
	conn := &StreamableHTTPConnection{
		requestData: body,
		writer:      w,
		ctx:         r.Context(),
		isStream:    false,
		response:    make(chan []byte, 1),
	}

	// Send connection to Accept()
	select {
	case t.connCh <- conn:
		// Wait for response
		select {
		case response := <-conn.response:
			w.Header().Set("Content-Type", "application/json")
			w.Write(response)
		case <-time.After(30 * time.Second):
			http.Error(w, "Request timeout", http.StatusRequestTimeout)
		case <-r.Context().Done():
			http.Error(w, "Request cancelled", http.StatusRequestTimeout)
		}
	default:
		http.Error(w, "Server busy", http.StatusServiceUnavailable)
	}
}

// StreamableHTTPConnection represents a streamable HTTP connection
type StreamableHTTPConnection struct {
	reader      *bufio.Reader
	writer      http.ResponseWriter
	flusher     http.Flusher
	ctx         context.Context
	requestData []byte
	response    chan []byte
	isStream    bool
	readPos     int
	mu          sync.Mutex
}

func (c *StreamableHTTPConnection) Read() ([]byte, error) {
	if c.isStream {
		// Read from streaming body
		if c.reader == nil {
			return nil, io.EOF
		}

		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			return nil, err
		}

		// Remove trailing newline
		if len(line) > 0 && line[len(line)-1] == '\n' {
			line = line[:len(line)-1]
		}
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		return line, nil
	} else {
		// Return single request data
		if c.readPos >= len(c.requestData) {
			return nil, io.EOF
		}

		data := c.requestData[c.readPos:]
		c.readPos = len(c.requestData)
		return data, nil
	}
}

func (c *StreamableHTTPConnection) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.isStream {
		// Write to streaming response
		_, err := c.writer.Write(append(data, '\n'))
		if err != nil {
			return err
		}

		if c.flusher != nil {
			c.flusher.Flush()
		}

		return nil
	} else {
		// Send single response
		select {
		case c.response <- data:
			return nil
		default:
			return fmt.Errorf("response channel full")
		}
	}
}

func (c *StreamableHTTPConnection) Close() error {
	if c.response != nil {
		close(c.response)
	}
	return nil
}

func (c *StreamableHTTPConnection) Context() context.Context {
	return c.ctx
}

func (c *StreamableHTTPConnection) RemoteAddr() string {
	return "http-client"
}
