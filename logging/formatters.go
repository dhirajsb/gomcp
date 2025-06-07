package logging

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// JSONFormatter formats log entries as JSON
type JSONFormatter struct {
	PrettyPrint    bool   `json:"pretty_print"`
	TimestampKey   string `json:"timestamp_key"`
	LevelKey       string `json:"level_key"`
	MessageKey     string `json:"message_key"`
	CallerKey      string `json:"caller_key"`
	StackKey       string `json:"stack_key"`
	ErrorKey       string `json:"error_key"`
	TimestampFormat string `json:"timestamp_format"`
}

// NewJSONFormatter creates a new JSON formatter
func NewJSONFormatter(prettyPrint bool) *JSONFormatter {
	return &JSONFormatter{
		PrettyPrint:     prettyPrint,
		TimestampKey:    "timestamp",
		LevelKey:        "level",
		MessageKey:      "message",
		CallerKey:       "caller",
		StackKey:        "stack",
		ErrorKey:        "error",
		TimestampFormat: time.RFC3339Nano,
	}
}

// Format formats a log entry as JSON
func (f *JSONFormatter) Format(entry *LogEntry) ([]byte, error) {
	data := make(map[string]interface{})
	
	// Core fields
	data[f.TimestampKey] = entry.Timestamp.Format(f.TimestampFormat)
	data[f.LevelKey] = entry.Level.String()
	data[f.MessageKey] = entry.Message
	
	// Optional fields
	if entry.Logger != "" {
		data["logger"] = entry.Logger
	}
	if entry.Component != "" {
		data["component"] = entry.Component
	}
	if entry.UserID != "" {
		data["user_id"] = entry.UserID
	}
	if entry.SessionID != "" {
		data["session_id"] = entry.SessionID
	}
	if entry.RequestID != "" {
		data["request_id"] = entry.RequestID
	}
	if entry.TraceID != "" {
		data["trace_id"] = entry.TraceID
	}
	if entry.SpanID != "" {
		data["span_id"] = entry.SpanID
	}
	if entry.Duration > 0 {
		data["duration"] = entry.Duration.String()
	}
	if entry.Error != "" {
		data[f.ErrorKey] = entry.Error
	}
	if len(entry.Tags) > 0 {
		data["tags"] = entry.Tags
	}
	
	// Caller info
	if entry.Caller != nil {
		data[f.CallerKey] = fmt.Sprintf("%s:%d", entry.Caller.File, entry.Caller.Line)
		data["function"] = entry.Caller.Function
	}
	
	// Stack trace
	if entry.Stack != "" {
		data[f.StackKey] = entry.Stack
	}
	
	// Additional fields
	for k, v := range entry.Fields {
		data[k] = v
	}
	
	// Metadata
	for k, v := range entry.Metadata {
		data[k] = v
	}
	
	if f.PrettyPrint {
		return json.MarshalIndent(data, "", "  ")
	}
	
	return json.Marshal(data)
}

// Type returns the formatter type
func (f *JSONFormatter) Type() string {
	return "json"
}

// TextFormatter formats log entries as human-readable text
type TextFormatter struct {
	TimestampFormat string `json:"timestamp_format"`
	ColorOutput     bool   `json:"color_output"`
	FullTimestamp   bool   `json:"full_timestamp"`
	PadLevelText    bool   `json:"pad_level_text"`
	QuoteEmptyFields bool  `json:"quote_empty_fields"`
	SortFields      bool   `json:"sort_fields"`
}

// NewTextFormatter creates a new text formatter
func NewTextFormatter(colorOutput bool) *TextFormatter {
	return &TextFormatter{
		TimestampFormat:  "2006-01-02 15:04:05",
		ColorOutput:      colorOutput,
		FullTimestamp:    true,
		PadLevelText:     true,
		QuoteEmptyFields: true,
		SortFields:       true,
	}
}

// ANSI color codes
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorGray   = "\033[37m"
	ColorWhite  = "\033[97m"
	ColorCyan   = "\033[36m"
)

// getLevelColor returns the ANSI color code for a log level
func (f *TextFormatter) getLevelColor(level LogLevel) string {
	if !f.ColorOutput {
		return ""
	}
	
	switch level {
	case LogLevelTrace:
		return ColorGray
	case LogLevelDebug:
		return ColorCyan
	case LogLevelInfo:
		return ColorBlue
	case LogLevelWarn:
		return ColorYellow
	case LogLevelError, LogLevelFatal:
		return ColorRed
	default:
		return ColorWhite
	}
}

// Format formats a log entry as text
func (f *TextFormatter) Format(entry *LogEntry) ([]byte, error) {
	var buf bytes.Buffer
	
	// Timestamp
	if f.FullTimestamp {
		buf.WriteString(entry.Timestamp.Format(f.TimestampFormat))
		buf.WriteByte(' ')
	}
	
	// Level with color
	levelColor := f.getLevelColor(entry.Level)
	if levelColor != "" {
		buf.WriteString(levelColor)
	}
	
	levelText := entry.Level.String()
	if f.PadLevelText {
		levelText = fmt.Sprintf("%-5s", levelText)
	}
	buf.WriteString(levelText)
	
	if levelColor != "" {
		buf.WriteString(ColorReset)
	}
	buf.WriteByte(' ')
	
	// Component/Logger
	if entry.Component != "" {
		buf.WriteByte('[')
		buf.WriteString(entry.Component)
		buf.WriteByte(']')
		buf.WriteByte(' ')
	} else if entry.Logger != "" {
		buf.WriteByte('[')
		buf.WriteString(entry.Logger)
		buf.WriteByte(']')
		buf.WriteByte(' ')
	}
	
	// Message
	buf.WriteString(entry.Message)
	
	// Fields
	if len(entry.Fields) > 0 {
		buf.WriteByte(' ')
		f.writeFields(&buf, entry.Fields)
	}
	
	// Context fields
	var contextFields []string
	if entry.UserID != "" {
		contextFields = append(contextFields, fmt.Sprintf("user_id=%s", entry.UserID))
	}
	if entry.SessionID != "" {
		contextFields = append(contextFields, fmt.Sprintf("session_id=%s", entry.SessionID))
	}
	if entry.RequestID != "" {
		contextFields = append(contextFields, fmt.Sprintf("request_id=%s", entry.RequestID))
	}
	if entry.TraceID != "" {
		contextFields = append(contextFields, fmt.Sprintf("trace_id=%s", entry.TraceID))
	}
	if entry.Duration > 0 {
		contextFields = append(contextFields, fmt.Sprintf("duration=%s", entry.Duration))
	}
	
	if len(contextFields) > 0 {
		buf.WriteByte(' ')
		buf.WriteString(strings.Join(contextFields, " "))
	}
	
	// Error
	if entry.Error != "" {
		buf.WriteString(" error=")
		buf.WriteString(strconv.Quote(entry.Error))
	}
	
	// Caller
	if entry.Caller != nil {
		buf.WriteString(fmt.Sprintf(" caller=%s:%d", entry.Caller.File, entry.Caller.Line))
	}
	
	// Tags
	if len(entry.Tags) > 0 {
		buf.WriteString(" tags=")
		buf.WriteString(strings.Join(entry.Tags, ","))
	}
	
	buf.WriteByte('\n')
	
	// Stack trace (on separate lines)
	if entry.Stack != "" {
		buf.WriteString("Stack trace:\n")
		buf.WriteString(entry.Stack)
		if !strings.HasSuffix(entry.Stack, "\n") {
			buf.WriteByte('\n')
		}
	}
	
	return buf.Bytes(), nil
}

// writeFields writes fields to the buffer
func (f *TextFormatter) writeFields(buf *bytes.Buffer, fields map[string]interface{}) {
	if len(fields) == 0 {
		return
	}
	
	var keys []string
	for k := range fields {
		keys = append(keys, k)
	}
	
	if f.SortFields {
		sort.Strings(keys)
	}
	
	for i, key := range keys {
		if i > 0 {
			buf.WriteByte(' ')
		}
		
		buf.WriteString(key)
		buf.WriteByte('=')
		
		value := fields[key]
		f.writeValue(buf, value)
	}
}

// writeValue writes a field value to the buffer
func (f *TextFormatter) writeValue(buf *bytes.Buffer, value interface{}) {
	switch v := value.(type) {
	case string:
		if v == "" && f.QuoteEmptyFields {
			buf.WriteString(`""`)
		} else if strings.ContainsAny(v, " \t\n\r") {
			buf.WriteString(strconv.Quote(v))
		} else {
			buf.WriteString(v)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		buf.WriteString(fmt.Sprintf("%d", v))
	case float32, float64:
		buf.WriteString(fmt.Sprintf("%g", v))
	case bool:
		buf.WriteString(fmt.Sprintf("%t", v))
	case time.Time:
		buf.WriteString(v.Format(time.RFC3339))
	case time.Duration:
		buf.WriteString(v.String())
	default:
		// For complex types, use JSON representation
		if data, err := json.Marshal(v); err == nil {
			buf.Write(data)
		} else {
			buf.WriteString(fmt.Sprintf("%+v", v))
		}
	}
}

// Type returns the formatter type
func (f *TextFormatter) Type() string {
	return "text"
}

// LogfmtFormatter formats log entries in logfmt format
type LogfmtFormatter struct {
	TimestampFormat string `json:"timestamp_format"`
	SortFields      bool   `json:"sort_fields"`
}

// NewLogfmtFormatter creates a new logfmt formatter
func NewLogfmtFormatter() *LogfmtFormatter {
	return &LogfmtFormatter{
		TimestampFormat: time.RFC3339,
		SortFields:      true,
	}
}

// Format formats a log entry in logfmt format
func (f *LogfmtFormatter) Format(entry *LogEntry) ([]byte, error) {
	var buf bytes.Buffer
	
	// Core fields
	f.writeKV(&buf, "timestamp", entry.Timestamp.Format(f.TimestampFormat))
	f.writeKV(&buf, "level", entry.Level.String())
	f.writeKV(&buf, "message", entry.Message)
	
	// Optional core fields
	if entry.Logger != "" {
		f.writeKV(&buf, "logger", entry.Logger)
	}
	if entry.Component != "" {
		f.writeKV(&buf, "component", entry.Component)
	}
	if entry.UserID != "" {
		f.writeKV(&buf, "user_id", entry.UserID)
	}
	if entry.SessionID != "" {
		f.writeKV(&buf, "session_id", entry.SessionID)
	}
	if entry.RequestID != "" {
		f.writeKV(&buf, "request_id", entry.RequestID)
	}
	if entry.TraceID != "" {
		f.writeKV(&buf, "trace_id", entry.TraceID)
	}
	if entry.SpanID != "" {
		f.writeKV(&buf, "span_id", entry.SpanID)
	}
	if entry.Duration > 0 {
		f.writeKV(&buf, "duration", entry.Duration.String())
	}
	if entry.Error != "" {
		f.writeKV(&buf, "error", entry.Error)
	}
	
	// Caller
	if entry.Caller != nil {
		f.writeKV(&buf, "caller", fmt.Sprintf("%s:%d", entry.Caller.File, entry.Caller.Line))
		f.writeKV(&buf, "function", entry.Caller.Function)
	}
	
	// Tags
	if len(entry.Tags) > 0 {
		f.writeKV(&buf, "tags", strings.Join(entry.Tags, ","))
	}
	
	// Additional fields
	if len(entry.Fields) > 0 {
		var keys []string
		for k := range entry.Fields {
			keys = append(keys, k)
		}
		
		if f.SortFields {
			sort.Strings(keys)
		}
		
		for _, key := range keys {
			f.writeKV(&buf, key, entry.Fields[key])
		}
	}
	
	// Metadata
	if len(entry.Metadata) > 0 {
		var keys []string
		for k := range entry.Metadata {
			keys = append(keys, k)
		}
		
		if f.SortFields {
			sort.Strings(keys)
		}
		
		for _, key := range keys {
			f.writeKV(&buf, key, entry.Metadata[key])
		}
	}
	
	buf.WriteByte('\n')
	
	// Stack trace (on separate line)
	if entry.Stack != "" {
		buf.WriteString("stack=")
		buf.WriteString(strconv.Quote(entry.Stack))
		buf.WriteByte('\n')
	}
	
	return buf.Bytes(), nil
}

// writeKV writes a key-value pair in logfmt format
func (f *LogfmtFormatter) writeKV(buf *bytes.Buffer, key string, value interface{}) {
	if buf.Len() > 0 {
		buf.WriteByte(' ')
	}
	
	buf.WriteString(key)
	buf.WriteByte('=')
	
	switch v := value.(type) {
	case string:
		if strings.ContainsAny(v, " \t\n\r=\"") || v == "" {
			buf.WriteString(strconv.Quote(v))
		} else {
			buf.WriteString(v)
		}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		buf.WriteString(fmt.Sprintf("%d", v))
	case float32, float64:
		buf.WriteString(fmt.Sprintf("%g", v))
	case bool:
		buf.WriteString(fmt.Sprintf("%t", v))
	case time.Time:
		buf.WriteString(v.Format(time.RFC3339))
	case time.Duration:
		buf.WriteString(v.String())
	default:
		// For complex types, use JSON representation
		if data, err := json.Marshal(v); err == nil {
			buf.WriteString(strconv.Quote(string(data)))
		} else {
			buf.WriteString(strconv.Quote(fmt.Sprintf("%+v", v)))
		}
	}
}

// Type returns the formatter type
func (f *LogfmtFormatter) Type() string {
	return "logfmt"
}