package loggers

import (
	"encoding/json"
	"log"
	"time"

	"github.com/dhirajsb/gomcp/internal/logging"
)

// JSONLogger implements a JSON formatter logger
type JSONLogger struct {
	name  string
	level logging.LogLevel
}

// NewJSON creates a new JSON logger
func NewJSON(name, level string) *JSONLogger {
	logLevel := parseLogLevel(level)
	return &JSONLogger{
		name:  name,
		level: logLevel,
	}
}

func (jl *JSONLogger) Name() string {
	return jl.name
}

func (jl *JSONLogger) Log(level logging.LogLevel, message string, fields map[string]interface{}) {
	if level < jl.level {
		return
	}

	logEntry := map[string]interface{}{
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"level":     level.String(),
		"logger":    jl.name,
		"message":   message,
	}

	for k, v := range fields {
		logEntry[k] = v
	}

	// Use proper JSON marshaling
	if jsonBytes, err := json.Marshal(logEntry); err == nil {
		log.Printf("%s", string(jsonBytes))
	} else {
		// Fallback to simple format
		log.Printf(`{"timestamp":"%s","level":"%s","logger":"%s","message":"%s"}`,
			logEntry["timestamp"], logEntry["level"], logEntry["logger"], logEntry["message"])
	}
}

func (jl *JSONLogger) Close() error {
	return nil
}
