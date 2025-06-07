package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
)

// LogLevel represents the severity level of a log entry
type LogLevel int

const (
	LogLevelTrace LogLevel = iota
	LogLevelDebug
	LogLevelInfo
	LogLevelWarn
	LogLevelError
	LogLevelFatal
)

// String returns the string representation of the log level
func (l LogLevel) String() string {
	switch l {
	case LogLevelTrace:
		return "TRACE"
	case LogLevelDebug:
		return "DEBUG"
	case LogLevelInfo:
		return "INFO"
	case LogLevelWarn:
		return "WARN"
	case LogLevelError:
		return "ERROR"
	case LogLevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// LogEntry represents a single log entry
type LogEntry struct {
	Timestamp   time.Time              `json:"timestamp"`
	Level       LogLevel               `json:"level"`
	Message     string                 `json:"message"`
	Fields      map[string]interface{} `json:"fields,omitempty"`
	Logger      string                 `json:"logger,omitempty"`
	Component   string                 `json:"component,omitempty"`
	UserID      string                 `json:"user_id,omitempty"`
	SessionID   string                 `json:"session_id,omitempty"`
	RequestID   string                 `json:"request_id,omitempty"`
	TraceID     string                 `json:"trace_id,omitempty"`
	SpanID      string                 `json:"span_id,omitempty"`
	Caller      *CallerInfo            `json:"caller,omitempty"`
	Stack       string                 `json:"stack,omitempty"`
	Duration    time.Duration          `json:"duration,omitempty"`
	Error       string                 `json:"error,omitempty"`
	Tags        []string               `json:"tags,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// CallerInfo holds information about the caller
type CallerInfo struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Function string `json:"function"`
}

// Logger defines the interface for loggers
type Logger interface {
	// Basic logging methods
	Trace(msg string, fields ...Field)
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	Fatal(msg string, fields ...Field)
	
	// Formatted logging methods
	Tracef(format string, args ...interface{})
	Debugf(format string, args ...interface{})
	Infof(format string, args ...interface{})
	Warnf(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	
	// Context-aware logging
	WithContext(ctx context.Context) Logger
	WithFields(fields ...Field) Logger
	WithComponent(component string) Logger
	WithUser(userID string) Logger
	WithSession(sessionID string) Logger
	WithRequest(requestID string) Logger
	WithTrace(traceID, spanID string) Logger
	WithError(err error) Logger
	WithTags(tags ...string) Logger
	
	// Configuration
	SetLevel(level LogLevel)
	GetLevel() LogLevel
	IsEnabled(level LogLevel) bool
	
	// Output management
	AddOutput(output LogOutput) error
	RemoveOutput(name string) error
	SetFormatter(formatter LogFormatter)
	
	// Metrics
	GetStats() LoggerStats
	
	// Lifecycle
	Flush() error
	Close() error
}

// Field represents a structured logging field
type Field struct {
	Key   string      `json:"key"`
	Value interface{} `json:"value"`
}

// LogOutput defines the interface for log outputs
type LogOutput interface {
	Write(entry *LogEntry) error
	Flush() error
	Close() error
	Name() string
	Type() string
}

// LogFormatter defines the interface for log formatters
type LogFormatter interface {
	Format(entry *LogEntry) ([]byte, error)
	Type() string
}

// LoggerConfig holds logger configuration
type LoggerConfig struct {
	Name         string                 `json:"name"`
	Level        LogLevel               `json:"level"`
	Component    string                 `json:"component"`
	Outputs      []OutputConfig         `json:"outputs"`
	Formatter    string                 `json:"formatter"`    // "json", "text", "logfmt"
	IncludeCaller bool                  `json:"include_caller"`
	IncludeStack bool                   `json:"include_stack"`
	Async        bool                   `json:"async"`
	BufferSize   int                    `json:"buffer_size"`
	FlushInterval time.Duration         `json:"flush_interval"`
	Config       map[string]interface{} `json:"config"`
}

// OutputConfig holds output configuration
type OutputConfig struct {
	Name     string                 `json:"name"`
	Type     string                 `json:"type"`     // "file", "stdout", "stderr", "syslog", "webhook", "elasticsearch"
	Level    LogLevel               `json:"level"`    // Minimum level for this output
	Enabled  bool                   `json:"enabled"`
	Config   map[string]interface{} `json:"config"`
}

// LoggerStats holds logger statistics
type LoggerStats struct {
	Name         string        `json:"name"`
	Level        LogLevel      `json:"level"`
	TotalEntries int64         `json:"total_entries"`
	EntriesByLevel map[LogLevel]int64 `json:"entries_by_level"`
	ErrorCount   int64         `json:"error_count"`
	LastEntry    time.Time     `json:"last_entry"`
	Uptime       time.Duration `json:"uptime"`
	OutputStats  map[string]OutputStats `json:"output_stats"`
}

// OutputStats holds output statistics
type OutputStats struct {
	Name         string    `json:"name"`
	Type         string    `json:"type"`
	Entries      int64     `json:"entries"`
	Errors       int64     `json:"errors"`
	LastWrite    time.Time `json:"last_write"`
	LastError    string    `json:"last_error"`
}

// StandardLogger implements the Logger interface
type StandardLogger struct {
	config        LoggerConfig
	level         LogLevel
	outputs       map[string]LogOutput
	formatter     LogFormatter
	fields        map[string]interface{}
	component     string
	stats         *LoggerStats
	entryChan     chan *LogEntry
	mu            sync.RWMutex
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	startTime     time.Time
}

// NewLogger creates a new standard logger
func NewLogger(config LoggerConfig) (*StandardLogger, error) {
	if config.Name == "" {
		config.Name = "default"
	}
	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 5 * time.Second
	}
	
	ctx, cancel := context.WithCancel(context.Background())
	
	logger := &StandardLogger{
		config:    config,
		level:     config.Level,
		outputs:   make(map[string]LogOutput),
		fields:    make(map[string]interface{}),
		component: config.Component,
		stats: &LoggerStats{
			Name:           config.Name,
			Level:          config.Level,
			EntriesByLevel: make(map[LogLevel]int64),
			OutputStats:    make(map[string]OutputStats),
		},
		ctx:       ctx,
		cancel:    cancel,
		startTime: time.Now(),
	}
	
	// Set formatter
	if err := logger.setFormatter(config.Formatter); err != nil {
		return nil, fmt.Errorf("failed to set formatter: %w", err)
	}
	
	// Initialize outputs
	for _, outputConfig := range config.Outputs {
		if err := logger.addOutput(outputConfig); err != nil {
			return nil, fmt.Errorf("failed to add output %s: %w", outputConfig.Name, err)
		}
	}
	
	// Start async processing if enabled
	if config.Async {
		logger.entryChan = make(chan *LogEntry, config.BufferSize)
		logger.wg.Add(1)
		go logger.processEntries()
		
		// Start flush timer
		logger.wg.Add(1)
		go logger.flushTimer()
	}
	
	return logger, nil
}

// setFormatter sets the log formatter
func (l *StandardLogger) setFormatter(formatterType string) error {
	switch formatterType {
	case "json", "":
		l.formatter = &JSONFormatter{}
	case "text":
		l.formatter = &TextFormatter{}
	case "logfmt":
		l.formatter = &LogfmtFormatter{}
	default:
		return fmt.Errorf("unknown formatter type: %s", formatterType)
	}
	return nil
}

// addOutput adds a log output
func (l *StandardLogger) addOutput(config OutputConfig) error {
	var output LogOutput
	var err error
	
	switch config.Type {
	case "stdout":
		output = NewConsoleOutput(config.Name, os.Stdout, config)
	case "stderr":
		output = NewConsoleOutput(config.Name, os.Stderr, config)
	case "file":
		output, err = NewFileOutput(config.Name, config)
	case "syslog":
		output, err = NewSyslogOutput(config.Name, config)
	case "webhook":
		output, err = NewWebhookOutput(config.Name, config)
	case "elasticsearch":
		output, err = NewElasticsearchOutput(config.Name, config)
	default:
		return fmt.Errorf("unknown output type: %s", config.Type)
	}
	
	if err != nil {
		return err
	}
	
	l.outputs[config.Name] = output
	l.stats.OutputStats[config.Name] = OutputStats{
		Name: config.Name,
		Type: config.Type,
	}
	
	return nil
}

// Log writes a log entry
func (l *StandardLogger) log(level LogLevel, msg string, fields ...Field) {
	if !l.IsEnabled(level) {
		return
	}
	
	entry := l.createEntry(level, msg, fields...)
	
	if l.config.Async {
		select {
		case l.entryChan <- entry:
		default:
			// Buffer full, drop entry or handle overflow
			l.stats.ErrorCount++
		}
	} else {
		l.writeEntry(entry)
	}
}

// createEntry creates a new log entry
func (l *StandardLogger) createEntry(level LogLevel, msg string, fields ...Field) *LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	entry := &LogEntry{
		Timestamp: time.Now(),
		Level:     level,
		Message:   msg,
		Fields:    make(map[string]interface{}),
		Logger:    l.config.Name,
		Component: l.component,
	}
	
	// Add logger fields
	for k, v := range l.fields {
		entry.Fields[k] = v
	}
	
	// Add entry fields
	for _, field := range fields {
		entry.Fields[field.Key] = field.Value
	}
	
	// Add caller info if enabled
	if l.config.IncludeCaller {
		if caller := getCaller(3); caller != nil {
			entry.Caller = caller
		}
	}
	
	// Add stack trace if enabled and error level
	if l.config.IncludeStack && level >= LogLevelError {
		entry.Stack = getStack(3)
	}
	
	return entry
}

// writeEntry writes an entry to all outputs
func (l *StandardLogger) writeEntry(entry *LogEntry) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	l.stats.TotalEntries++
	l.stats.EntriesByLevel[entry.Level]++
	l.stats.LastEntry = entry.Timestamp
	
	for name, output := range l.outputs {
		if err := output.Write(entry); err != nil {
			l.stats.ErrorCount++
			stats := l.stats.OutputStats[name]
			stats.Errors++
			stats.LastError = err.Error()
			l.stats.OutputStats[name] = stats
		} else {
			stats := l.stats.OutputStats[name]
			stats.Entries++
			stats.LastWrite = entry.Timestamp
			l.stats.OutputStats[name] = stats
		}
	}
}

// processEntries processes log entries asynchronously
func (l *StandardLogger) processEntries() {
	defer l.wg.Done()
	
	for {
		select {
		case entry := <-l.entryChan:
			l.writeEntry(entry)
		case <-l.ctx.Done():
			// Drain remaining entries
			for {
				select {
				case entry := <-l.entryChan:
					l.writeEntry(entry)
				default:
					return
				}
			}
		}
	}
}

// flushTimer periodically flushes outputs
func (l *StandardLogger) flushTimer() {
	defer l.wg.Done()
	
	ticker := time.NewTicker(l.config.FlushInterval)
	defer ticker.Stop()
	
	for {
		select {
		case <-ticker.C:
			l.Flush()
		case <-l.ctx.Done():
			return
		}
	}
}

// Basic logging methods
func (l *StandardLogger) Trace(msg string, fields ...Field) { l.log(LogLevelTrace, msg, fields...) }
func (l *StandardLogger) Debug(msg string, fields ...Field) { l.log(LogLevelDebug, msg, fields...) }
func (l *StandardLogger) Info(msg string, fields ...Field)  { l.log(LogLevelInfo, msg, fields...) }
func (l *StandardLogger) Warn(msg string, fields ...Field)  { l.log(LogLevelWarn, msg, fields...) }
func (l *StandardLogger) Error(msg string, fields ...Field) { l.log(LogLevelError, msg, fields...) }
func (l *StandardLogger) Fatal(msg string, fields ...Field) {
	l.log(LogLevelFatal, msg, fields...)
	l.Flush()
	os.Exit(1)
}

// Formatted logging methods
func (l *StandardLogger) Tracef(format string, args ...interface{}) {
	l.log(LogLevelTrace, fmt.Sprintf(format, args...))
}
func (l *StandardLogger) Debugf(format string, args ...interface{}) {
	l.log(LogLevelDebug, fmt.Sprintf(format, args...))
}
func (l *StandardLogger) Infof(format string, args ...interface{}) {
	l.log(LogLevelInfo, fmt.Sprintf(format, args...))
}
func (l *StandardLogger) Warnf(format string, args ...interface{}) {
	l.log(LogLevelWarn, fmt.Sprintf(format, args...))
}
func (l *StandardLogger) Errorf(format string, args ...interface{}) {
	l.log(LogLevelError, fmt.Sprintf(format, args...))
}
func (l *StandardLogger) Fatalf(format string, args ...interface{}) {
	l.log(LogLevelFatal, fmt.Sprintf(format, args...))
	l.Flush()
	os.Exit(1)
}

// WithContext creates a logger with context
func (l *StandardLogger) WithContext(ctx context.Context) Logger {
	newLogger := l.copy()
	
	// Extract context values
	if userID := ctx.Value("user_id"); userID != nil {
		if uid, ok := userID.(string); ok {
			newLogger.fields["user_id"] = uid
		}
	}
	if sessionID := ctx.Value("session_id"); sessionID != nil {
		if sid, ok := sessionID.(string); ok {
			newLogger.fields["session_id"] = sid
		}
	}
	if requestID := ctx.Value("request_id"); requestID != nil {
		if rid, ok := requestID.(string); ok {
			newLogger.fields["request_id"] = rid
		}
	}
	if traceID := ctx.Value("trace_id"); traceID != nil {
		if tid, ok := traceID.(string); ok {
			newLogger.fields["trace_id"] = tid
		}
	}
	if spanID := ctx.Value("span_id"); spanID != nil {
		if sid, ok := spanID.(string); ok {
			newLogger.fields["span_id"] = sid
		}
	}
	
	return newLogger
}

// WithFields creates a logger with additional fields
func (l *StandardLogger) WithFields(fields ...Field) Logger {
	newLogger := l.copy()
	for _, field := range fields {
		newLogger.fields[field.Key] = field.Value
	}
	return newLogger
}

// WithComponent creates a logger with a component name
func (l *StandardLogger) WithComponent(component string) Logger {
	newLogger := l.copy()
	newLogger.component = component
	return newLogger
}

// WithUser creates a logger with user ID
func (l *StandardLogger) WithUser(userID string) Logger {
	newLogger := l.copy()
	newLogger.fields["user_id"] = userID
	return newLogger
}

// WithSession creates a logger with session ID
func (l *StandardLogger) WithSession(sessionID string) Logger {
	newLogger := l.copy()
	newLogger.fields["session_id"] = sessionID
	return newLogger
}

// WithRequest creates a logger with request ID
func (l *StandardLogger) WithRequest(requestID string) Logger {
	newLogger := l.copy()
	newLogger.fields["request_id"] = requestID
	return newLogger
}

// WithTrace creates a logger with trace and span IDs
func (l *StandardLogger) WithTrace(traceID, spanID string) Logger {
	newLogger := l.copy()
	newLogger.fields["trace_id"] = traceID
	newLogger.fields["span_id"] = spanID
	return newLogger
}

// WithError creates a logger with error information
func (l *StandardLogger) WithError(err error) Logger {
	newLogger := l.copy()
	newLogger.fields["error"] = err.Error()
	return newLogger
}

// WithTags creates a logger with tags
func (l *StandardLogger) WithTags(tags ...string) Logger {
	newLogger := l.copy()
	newLogger.fields["tags"] = tags
	return newLogger
}

// copy creates a copy of the logger for chaining
func (l *StandardLogger) copy() *StandardLogger {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	newFields := make(map[string]interface{})
	for k, v := range l.fields {
		newFields[k] = v
	}
	
	return &StandardLogger{
		config:    l.config,
		level:     l.level,
		outputs:   l.outputs,
		formatter: l.formatter,
		fields:    newFields,
		component: l.component,
		stats:     l.stats,
		entryChan: l.entryChan,
		ctx:       l.ctx,
		cancel:    l.cancel,
		startTime: l.startTime,
	}
}

// Configuration methods
func (l *StandardLogger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
	l.stats.Level = level
}

func (l *StandardLogger) GetLevel() LogLevel {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.level
}

func (l *StandardLogger) IsEnabled(level LogLevel) bool {
	return level >= l.GetLevel()
}

// Output management
func (l *StandardLogger) AddOutput(output LogOutput) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	l.outputs[output.Name()] = output
	l.stats.OutputStats[output.Name()] = OutputStats{
		Name: output.Name(),
		Type: output.Type(),
	}
	
	return nil
}

func (l *StandardLogger) RemoveOutput(name string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	if output, exists := l.outputs[name]; exists {
		output.Close()
		delete(l.outputs, name)
		delete(l.stats.OutputStats, name)
	}
	
	return nil
}

func (l *StandardLogger) SetFormatter(formatter LogFormatter) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.formatter = formatter
}

// Metrics
func (l *StandardLogger) GetStats() LoggerStats {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	stats := *l.stats // Copy stats
	stats.Uptime = time.Since(l.startTime)
	return stats
}

// Lifecycle
func (l *StandardLogger) Flush() error {
	l.mu.RLock()
	defer l.mu.RUnlock()
	
	var lastErr error
	for _, output := range l.outputs {
		if err := output.Flush(); err != nil {
			lastErr = err
		}
	}
	
	return lastErr
}

func (l *StandardLogger) Close() error {
	// Stop async processing
	if l.cancel != nil {
		l.cancel()
	}
	l.wg.Wait()
	
	// Close all outputs
	l.mu.Lock()
	defer l.mu.Unlock()
	
	var lastErr error
	for _, output := range l.outputs {
		if err := output.Close(); err != nil {
			lastErr = err
		}
	}
	
	return lastErr
}

// Utility functions
func getCaller(skip int) *CallerInfo {
	pc, file, line, ok := runtime.Caller(skip)
	if !ok {
		return nil
	}
	
	fn := runtime.FuncForPC(pc)
	if fn == nil {
		return nil
	}
	
	// Get short file name
	if idx := strings.LastIndex(file, "/"); idx >= 0 {
		file = file[idx+1:]
	}
	
	return &CallerInfo{
		File:     file,
		Line:     line,
		Function: fn.Name(),
	}
}

func getStack(skip int) string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

// Helper functions for creating fields
func String(key, value string) Field          { return Field{Key: key, Value: value} }
func Int(key string, value int) Field         { return Field{Key: key, Value: value} }
func Int64(key string, value int64) Field     { return Field{Key: key, Value: value} }
func Float64(key string, value float64) Field { return Field{Key: key, Value: value} }
func Bool(key string, value bool) Field       { return Field{Key: key, Value: value} }
func Duration(key string, value time.Duration) Field { return Field{Key: key, Value: value} }
func Time(key string, value time.Time) Field  { return Field{Key: key, Value: value} }
func Any(key string, value interface{}) Field { return Field{Key: key, Value: value} }