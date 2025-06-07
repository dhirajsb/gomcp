package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"sync"
)

// StdioTransport implements MCP over stdio
type StdioTransport struct {
	config StdioConfig
	conn   *StdioConnection
	once   sync.Once
}

// NewStdioTransport creates a new stdio transport
func NewStdioTransport(config StdioConfig) *StdioTransport {
	if config.Reader == nil {
		config.Reader = os.Stdin
	}
	if config.Writer == nil {
		config.Writer = os.Stdout
	}

	return &StdioTransport{
		config: config,
	}
}

func (t *StdioTransport) Listen() error {
	// Stdio doesn't need to listen
	return nil
}

func (t *StdioTransport) Accept() (Connection, error) {
	var err error
	t.once.Do(func() {
		t.conn = &StdioConnection{
			reader: bufio.NewReader(t.config.Reader),
			writer: t.config.Writer,
			ctx:    context.Background(),
		}
	})

	if t.conn == nil {
		return nil, fmt.Errorf("stdio connection already closed")
	}

	return t.conn, err
}

func (t *StdioTransport) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

func (t *StdioTransport) Type() string {
	return TransportStdio
}

// StdioConnection represents a stdio connection
type StdioConnection struct {
	reader *bufio.Reader
	writer io.Writer
	ctx    context.Context
	closed bool
	mu     sync.Mutex
}

func (c *StdioConnection) Read() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil, io.EOF
	}

	// Read JSON-RPC message line by line
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
}

func (c *StdioConnection) Write(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return fmt.Errorf("connection closed")
	}

	// Write message with newline
	_, err := c.writer.Write(append(data, '\n'))
	return err
}

func (c *StdioConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.closed = true
	return nil
}

func (c *StdioConnection) Context() context.Context {
	return c.ctx
}

func (c *StdioConnection) RemoteAddr() string {
	return "stdio"
}
