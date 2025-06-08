package security

import (
	"context"
	"fmt"

	"github.com/dhirajsb/gomcp/internal/types"
)

// StrictValidator implements strict security validation
type StrictValidator struct {
	name string
}

// NewStrict creates a new strict validator
func NewStrict(name string) *StrictValidator {
	return &StrictValidator{name: name}
}

func (sv *StrictValidator) Name() string {
	return sv.name
}

func (sv *StrictValidator) ValidateRequest(ctx context.Context, req *types.Request) error {
	if req == nil {
		return fmt.Errorf("request cannot be nil")
	}
	if req.Method == "" {
		return fmt.Errorf("method required")
	}

	// Add more strict validations as needed
	return nil
}

func (sv *StrictValidator) SanitizeParams(params map[string]interface{}) map[string]interface{} {
	if params == nil {
		return make(map[string]interface{})
	}
	// In strict mode, don't auto-sanitize, just return as-is
	return params
}
