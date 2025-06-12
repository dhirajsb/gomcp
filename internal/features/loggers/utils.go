package loggers

import (
	"strings"

	"github.com/dhirajsb/gomcp/pkg/features"
)

// parseLogLevel converts a string log level to LogLevel enum
func parseLogLevel(level string) features.LogLevel {
	switch strings.ToLower(level) {
	case "trace":
		return features.TRACE
	case "debug":
		return features.DEBUG
	case "info":
		return features.INFO
	case "warn", "warning":
		return features.WARN
	case "error":
		return features.ERROR
	case "fatal":
		return features.FATAL
	default:
		return features.INFO
	}
}
