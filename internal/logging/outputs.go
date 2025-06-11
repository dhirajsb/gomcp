package logging

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/syslog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/dhirajsb/gomcp/pkg/features"
)

// ConsoleOutput writes to console (stdout/stderr)
type ConsoleOutput struct {
	name      string
	writer    io.Writer
	formatter LogFormatter
	level     features.LogLevel
	mu        sync.Mutex
}

// NewConsoleOutput creates a new console output
func NewConsoleOutput(name string, writer io.Writer, config OutputConfig) *ConsoleOutput {
	formatter := NewTextFormatter(true) // Enable colors for console

	return &ConsoleOutput{
		name:      name,
		writer:    writer,
		formatter: formatter,
		level:     config.Level,
	}
}

func (o *ConsoleOutput) Write(entry *LogEntry) error {
	if entry.Level < o.level {
		return nil
	}

	data, err := o.formatter.Format(entry)
	if err != nil {
		return err
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	_, err = o.writer.Write(data)
	return err
}

func (o *ConsoleOutput) Flush() error {
	// Console output is unbuffered
	return nil
}

func (o *ConsoleOutput) Close() error {
	// Nothing to close for console output
	return nil
}

func (o *ConsoleOutput) Name() string {
	return o.name
}

func (o *ConsoleOutput) Type() string {
	return "console"
}

// FileOutput writes to files with rotation support
type FileOutput struct {
	name        string
	filename    string
	file        *os.File
	formatter   LogFormatter
	level       features.LogLevel
	maxSize     int64 // Max file size in bytes
	maxAge      int   // Max age in days
	maxBackups  int   // Max number of backup files
	compress    bool  // Compress backup files
	currentSize int64
	mu          sync.Mutex
}

// NewFileOutput creates a new file output
func NewFileOutput(name string, config OutputConfig) (*FileOutput, error) {
	filename := getStringConfig(config.Config, "filename", "app.log")
	maxSize := getIntConfig(config.Config, "max_size", 100*1024*1024) // 100MB
	maxAge := getIntConfig(config.Config, "max_age", 30)              // 30 days
	maxBackups := getIntConfig(config.Config, "max_backups", 10)
	compress := getBoolConfig(config.Config, "compress", true)

	// Create directory if needed
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %w", err)
	}

	// Open file
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return nil, fmt.Errorf("failed to open log file: %w", err)
	}

	// Get current file size
	stat, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("failed to stat log file: %w", err)
	}

	formatter := NewJSONFormatter(false) // Use compact JSON for files

	return &FileOutput{
		name:        name,
		filename:    filename,
		file:        file,
		formatter:   formatter,
		level:       config.Level,
		maxSize:     int64(maxSize),
		maxAge:      maxAge,
		maxBackups:  maxBackups,
		compress:    compress,
		currentSize: stat.Size(),
	}, nil
}

func (o *FileOutput) Write(entry *LogEntry) error {
	if entry.Level < o.level {
		return nil
	}

	data, err := o.formatter.Format(entry)
	if err != nil {
		return err
	}

	// Add newline if not present
	if !bytes.HasSuffix(data, []byte{'\n'}) {
		data = append(data, '\n')
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Check if rotation is needed
	if o.currentSize+int64(len(data)) > o.maxSize {
		if err := o.rotate(); err != nil {
			return err
		}
	}

	n, err := o.file.Write(data)
	if err != nil {
		return err
	}

	o.currentSize += int64(n)
	return nil
}

func (o *FileOutput) rotate() error {
	if err := o.file.Close(); err != nil {
		return err
	}

	// Generate backup filename
	backupName := fmt.Sprintf("%s.%s", o.filename, time.Now().Format("2006-01-02T15-04-05"))

	// Rename current file to backup
	if err := os.Rename(o.filename, backupName); err != nil {
		return err
	}

	// Compress backup if enabled
	if o.compress {
		go o.compressFile(backupName)
	}

	// Clean up old backups
	go o.cleanupBackups()

	// Create new file
	file, err := os.OpenFile(o.filename, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	o.file = file
	o.currentSize = 0

	return nil
}

func (o *FileOutput) compressFile(filename string) {
	// Simple gzip compression - can be improved
	// Implementation would use gzip package
}

func (o *FileOutput) cleanupBackups() {
	// Clean up old backup files based on maxAge and maxBackups
	// Implementation would scan directory and remove old files
}

func (o *FileOutput) Flush() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.file != nil {
		return o.file.Sync()
	}

	return nil
}

func (o *FileOutput) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.file != nil {
		err := o.file.Close()
		o.file = nil
		return err
	}

	return nil
}

func (o *FileOutput) Name() string {
	return o.name
}

func (o *FileOutput) Type() string {
	return "file"
}

// SyslogOutput writes to syslog
type SyslogOutput struct {
	name      string
	writer    *syslog.Writer
	formatter LogFormatter
	level     features.LogLevel
	mu        sync.Mutex
}

// NewSyslogOutput creates a new syslog output
func NewSyslogOutput(name string, config OutputConfig) (*SyslogOutput, error) {
	network := getStringConfig(config.Config, "network", "") // "tcp", "udp", or "" for local
	address := getStringConfig(config.Config, "address", "")
	tag := getStringConfig(config.Config, "tag", "gomcp")

	var writer *syslog.Writer
	var err error

	if network == "" {
		writer, err = syslog.New(syslog.LOG_INFO, tag)
	} else {
		writer, err = syslog.Dial(network, address, syslog.LOG_INFO, tag)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to syslog: %w", err)
	}

	formatter := NewTextFormatter(false) // No colors for syslog

	return &SyslogOutput{
		name:      name,
		writer:    writer,
		formatter: formatter,
		level:     config.Level,
	}, nil
}

func (o *SyslogOutput) Write(entry *LogEntry) error {
	if entry.Level < o.level {
		return nil
	}

	data, err := o.formatter.Format(entry)
	if err != nil {
		return err
	}

	// Remove trailing newline for syslog
	message := strings.TrimSuffix(string(data), "\n")

	o.mu.Lock()
	defer o.mu.Unlock()

	// Map log levels to syslog levels
	switch entry.Level {
	case features.TRACE, features.DEBUG:
		return o.writer.Debug(message)
	case features.INFO:
		return o.writer.Info(message)
	case features.WARN:
		return o.writer.Warning(message)
	case features.ERROR:
		return o.writer.Err(message)
	case features.FATAL:
		return o.writer.Crit(message)
	default:
		return o.writer.Info(message)
	}
}

func (o *SyslogOutput) Flush() error {
	// Syslog doesn't require explicit flushing
	return nil
}

func (o *SyslogOutput) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.writer != nil {
		err := o.writer.Close()
		o.writer = nil
		return err
	}

	return nil
}

func (o *SyslogOutput) Name() string {
	return o.name
}

func (o *SyslogOutput) Type() string {
	return "syslog"
}

// WebhookOutput sends logs to HTTP webhook
type WebhookOutput struct {
	name         string
	url          string
	client       *http.Client
	formatter    LogFormatter
	level        features.LogLevel
	buffer       []*LogEntry
	bufferSize   int
	batchTimeout time.Duration
	mu           sync.Mutex
	timer        *time.Timer
}

// NewWebhookOutput creates a new webhook output
func NewWebhookOutput(name string, config OutputConfig) (*WebhookOutput, error) {
	webhookURL := getStringConfig(config.Config, "url", "")
	if webhookURL == "" {
		return nil, fmt.Errorf("webhook URL is required")
	}

	timeout := time.Duration(getIntConfig(config.Config, "timeout", 30)) * time.Second
	bufferSize := getIntConfig(config.Config, "buffer_size", 100)
	batchTimeout := time.Duration(getIntConfig(config.Config, "batch_timeout", 5)) * time.Second
	insecureSkipVerify := getBoolConfig(config.Config, "insecure_skip_verify", false)

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}

	formatter := NewJSONFormatter(false)

	webhook := &WebhookOutput{
		name:         name,
		url:          webhookURL,
		client:       client,
		formatter:    formatter,
		level:        config.Level,
		buffer:       make([]*LogEntry, 0, bufferSize),
		bufferSize:   bufferSize,
		batchTimeout: batchTimeout,
	}

	// Start batch timer
	webhook.resetTimer()

	return webhook, nil
}

func (o *WebhookOutput) Write(entry *LogEntry) error {
	if entry.Level < o.level {
		return nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.buffer = append(o.buffer, entry)

	// Send if buffer is full
	if len(o.buffer) >= o.bufferSize {
		return o.sendBatch()
	}

	return nil
}

func (o *WebhookOutput) sendBatch() error {
	if len(o.buffer) == 0 {
		return nil
	}

	// Format all entries
	var entries []map[string]interface{}
	for _, entry := range o.buffer {
		data, err := o.formatter.Format(entry)
		if err != nil {
			continue
		}

		var entryMap map[string]interface{}
		if err := json.Unmarshal(data, &entryMap); err != nil {
			continue
		}

		entries = append(entries, entryMap)
	}

	// Create payload
	payload := map[string]interface{}{
		"logs":      entries,
		"timestamp": time.Now(),
		"source":    "gomcp",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	// Send HTTP request
	resp, err := o.client.Post(o.url, "application/json", bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	// Clear buffer
	o.buffer = o.buffer[:0]
	o.resetTimer()

	return nil
}

func (o *WebhookOutput) resetTimer() {
	if o.timer != nil {
		o.timer.Stop()
	}

	o.timer = time.AfterFunc(o.batchTimeout, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.sendBatch()
	})
}

func (o *WebhookOutput) Flush() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.sendBatch()
}

func (o *WebhookOutput) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.timer != nil {
		o.timer.Stop()
	}

	return o.sendBatch()
}

func (o *WebhookOutput) Name() string {
	return o.name
}

func (o *WebhookOutput) Type() string {
	return "webhook"
}

// ElasticsearchOutput sends logs to Elasticsearch
type ElasticsearchOutput struct {
	name         string
	baseURL      string
	index        string
	client       *http.Client
	formatter    LogFormatter
	level        features.LogLevel
	buffer       []*LogEntry
	bufferSize   int
	batchTimeout time.Duration
	mu           sync.Mutex
	timer        *time.Timer
}

// NewElasticsearchOutput creates a new Elasticsearch output
func NewElasticsearchOutput(name string, config OutputConfig) (*ElasticsearchOutput, error) {
	baseURL := getStringConfig(config.Config, "url", "http://localhost:9200")
	index := getStringConfig(config.Config, "index", "gomcp-logs")
	username := getStringConfig(config.Config, "username", "")
	password := getStringConfig(config.Config, "password", "")
	timeout := time.Duration(getIntConfig(config.Config, "timeout", 30)) * time.Second
	bufferSize := getIntConfig(config.Config, "buffer_size", 100)
	batchTimeout := time.Duration(getIntConfig(config.Config, "batch_timeout", 5)) * time.Second

	// Parse and validate URL
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid Elasticsearch URL: %w", err)
	}

	// Add authentication if provided
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	}

	client := &http.Client{
		Timeout: timeout,
	}

	formatter := NewJSONFormatter(false)

	es := &ElasticsearchOutput{
		name:         name,
		baseURL:      u.String(),
		index:        index,
		client:       client,
		formatter:    formatter,
		level:        config.Level,
		buffer:       make([]*LogEntry, 0, bufferSize),
		bufferSize:   bufferSize,
		batchTimeout: batchTimeout,
	}

	// Start batch timer
	es.resetTimer()

	return es, nil
}

func (o *ElasticsearchOutput) Write(entry *LogEntry) error {
	if entry.Level < o.level {
		return nil
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	o.buffer = append(o.buffer, entry)

	// Send if buffer is full
	if len(o.buffer) >= o.bufferSize {
		return o.sendBatch()
	}

	return nil
}

func (o *ElasticsearchOutput) sendBatch() error {
	if len(o.buffer) == 0 {
		return nil
	}

	// Build bulk request
	var bulk strings.Builder

	for _, entry := range o.buffer {
		// Index action
		indexAction := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": o.index,
				"_type":  "_doc",
			},
		}

		actionData, err := json.Marshal(indexAction)
		if err != nil {
			continue
		}

		bulk.Write(actionData)
		bulk.WriteByte('\n')

		// Document data
		docData, err := o.formatter.Format(entry)
		if err != nil {
			continue
		}

		bulk.Write(docData)
		bulk.WriteByte('\n')
	}

	// Send bulk request
	url := fmt.Sprintf("%s/_bulk", o.baseURL)
	req, err := http.NewRequest("POST", url, strings.NewReader(bulk.String()))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/x-ndjson")

	resp, err := o.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Elasticsearch returned status %d", resp.StatusCode)
	}

	// Clear buffer
	o.buffer = o.buffer[:0]
	o.resetTimer()

	return nil
}

func (o *ElasticsearchOutput) resetTimer() {
	if o.timer != nil {
		o.timer.Stop()
	}

	o.timer = time.AfterFunc(o.batchTimeout, func() {
		o.mu.Lock()
		defer o.mu.Unlock()
		o.sendBatch()
	})
}

func (o *ElasticsearchOutput) Flush() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	return o.sendBatch()
}

func (o *ElasticsearchOutput) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.timer != nil {
		o.timer.Stop()
	}

	return o.sendBatch()
}

func (o *ElasticsearchOutput) Name() string {
	return o.name
}

func (o *ElasticsearchOutput) Type() string {
	return "elasticsearch"
}

// Utility functions for parsing configuration
func getStringConfig(config map[string]interface{}, key, defaultValue string) string {
	if value, ok := config[key].(string); ok {
		return value
	}
	return defaultValue
}

func getIntConfig(config map[string]interface{}, key string, defaultValue int) int {
	if value, ok := config[key].(float64); ok {
		return int(value)
	}
	if value, ok := config[key].(int); ok {
		return value
	}
	return defaultValue
}

func getBoolConfig(config map[string]interface{}, key string, defaultValue bool) bool {
	if value, ok := config[key].(bool); ok {
		return value
	}
	return defaultValue
}
