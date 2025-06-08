package loggers

import (
	"fmt"
	"log"
	"strings"

	"github.com/dhirajsb/gomcp/internal/logging"
)

// ConsoleLogger implements a console logger that outputs to stdout
type ConsoleLogger struct {
	name  string
	level logging.LogLevel
}

// NewConsole creates a new console logger
func NewConsole(name, level string) *ConsoleLogger {
	logLevel := parseLogLevel(level)
	return &ConsoleLogger{
		name:  name,
		level: logLevel,
	}
}

func (cl *ConsoleLogger) Name() string {
	return cl.name
}

func (cl *ConsoleLogger) Log(level logging.LogLevel, message string, fields map[string]interface{}) {
	if level < cl.level {
		return
	}
	
	fieldsStr := ""
	if len(fields) > 0 {
		parts := make([]string, 0, len(fields))
		for k, v := range fields {
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		fieldsStr = fmt.Sprintf(" [%s]", strings.Join(parts, " "))
	}
	
	log.Printf("[%s] %s: %s%s", strings.ToUpper(level.String()), cl.name, message, fieldsStr)
}

func (cl *ConsoleLogger) Close() error {
	return nil
}

func parseLogLevel(level string) logging.LogLevel {
	switch strings.ToLower(level) {
	case "debug":
		return logging.LogLevelDebug
	case "info":
		return logging.LogLevelInfo
	case "warn", "warning":
		return logging.LogLevelWarn
	case "error":
		return logging.LogLevelError
	default:
		return logging.LogLevelInfo
	}
}