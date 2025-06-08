package cache

import (
	"sync"
	"time"
)

// CircuitBreakerState represents the state of a circuit breaker
type CircuitBreakerState int

const (
	CircuitBreakerClosed CircuitBreakerState = iota
	CircuitBreakerOpen
	CircuitBreakerHalfOpen
)

// CircuitBreakerConfig holds circuit breaker configuration
type CircuitBreakerConfig struct {
	MaxFailures  int           `json:"max_failures"`  // Maximum failures before opening
	Timeout      time.Duration `json:"timeout"`       // Timeout before trying half-open
	ResetTimeout time.Duration `json:"reset_timeout"` // Timeout before resetting to closed
	FailureRatio float64       `json:"failure_ratio"` // Failure ratio threshold (0.0-1.0)
	MinRequests  int           `json:"min_requests"`  // Minimum requests before evaluating ratio
}

// CircuitBreaker implements the circuit breaker pattern
type CircuitBreaker struct {
	config        CircuitBreakerConfig
	state         CircuitBreakerState
	failures      int
	requests      int
	successCount  int
	lastFailTime  time.Time
	lastStateTime time.Time
	mu            sync.RWMutex
	onStateChange func(from, to CircuitBreakerState)
}

// NewCircuitBreaker creates a new circuit breaker
func NewCircuitBreaker(config CircuitBreakerConfig) *CircuitBreaker {
	if config.MaxFailures == 0 {
		config.MaxFailures = 5
	}
	if config.Timeout == 0 {
		config.Timeout = 60 * time.Second
	}
	if config.ResetTimeout == 0 {
		config.ResetTimeout = 30 * time.Second
	}
	if config.FailureRatio == 0 {
		config.FailureRatio = 0.6 // 60% failure rate
	}
	if config.MinRequests == 0 {
		config.MinRequests = 10
	}

	return &CircuitBreaker{
		config:        config,
		state:         CircuitBreakerClosed,
		lastStateTime: time.Now(),
	}
}

// CanExecute checks if requests can be executed
func (cb *CircuitBreaker) CanExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	switch cb.state {
	case CircuitBreakerClosed:
		return true
	case CircuitBreakerOpen:
		// Check if timeout has passed to try half-open
		if time.Since(cb.lastStateTime) >= cb.config.Timeout {
			cb.mu.RUnlock()
			cb.mu.Lock()
			// Double-check after acquiring write lock
			if cb.state == CircuitBreakerOpen && time.Since(cb.lastStateTime) >= cb.config.Timeout {
				cb.setState(CircuitBreakerHalfOpen)
			}
			cb.mu.Unlock()
			cb.mu.RLock()
			return cb.state == CircuitBreakerHalfOpen
		}
		return false
	case CircuitBreakerHalfOpen:
		return true
	default:
		return false
	}
}

// RecordSuccess records a successful execution
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.requests++
	cb.successCount++

	switch cb.state {
	case CircuitBreakerHalfOpen:
		// After successful execution in half-open, reset to closed
		cb.setState(CircuitBreakerClosed)
		cb.resetCounters()
	case CircuitBreakerClosed:
		// Reset failure count on success
		cb.failures = 0
	}
}

// RecordFailure records a failed execution
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.requests++
	cb.failures++
	cb.lastFailTime = time.Now()

	switch cb.state {
	case CircuitBreakerClosed:
		if cb.shouldOpen() {
			cb.setState(CircuitBreakerOpen)
		}
	case CircuitBreakerHalfOpen:
		// Failure in half-open goes back to open
		cb.setState(CircuitBreakerOpen)
	}
}

// shouldOpen determines if the circuit breaker should open
func (cb *CircuitBreaker) shouldOpen() bool {
	// Check maximum failures threshold
	if cb.failures >= cb.config.MaxFailures {
		return true
	}

	// Check failure ratio if we have enough requests
	if cb.requests >= cb.config.MinRequests {
		failureRatio := float64(cb.failures) / float64(cb.requests)
		if failureRatio >= cb.config.FailureRatio {
			return true
		}
	}

	return false
}

// setState changes the circuit breaker state
func (cb *CircuitBreaker) setState(newState CircuitBreakerState) {
	if cb.state != newState {
		oldState := cb.state
		cb.state = newState
		cb.lastStateTime = time.Now()

		// Call state change callback if set
		if cb.onStateChange != nil {
			go cb.onStateChange(oldState, newState)
		}
	}
}

// resetCounters resets failure and request counters
func (cb *CircuitBreaker) resetCounters() {
	cb.failures = 0
	cb.requests = 0
	cb.successCount = 0
}

// GetState returns the current state
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// GetStats returns circuit breaker statistics
func (cb *CircuitBreaker) GetStats() CircuitBreakerStats {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	var failureRatio float64
	if cb.requests > 0 {
		failureRatio = float64(cb.failures) / float64(cb.requests)
	}

	return CircuitBreakerStats{
		State:         cb.state,
		Failures:      cb.failures,
		Requests:      cb.requests,
		SuccessCount:  cb.successCount,
		FailureRatio:  failureRatio,
		LastFailTime:  cb.lastFailTime,
		LastStateTime: cb.lastStateTime,
		StateUptime:   time.Since(cb.lastStateTime),
	}
}

// SetOnStateChange sets a callback for state changes
func (cb *CircuitBreaker) SetOnStateChange(callback func(from, to CircuitBreakerState)) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.onStateChange = callback
}

// Reset resets the circuit breaker to closed state
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.setState(CircuitBreakerClosed)
	cb.resetCounters()
}

// ForceOpen forces the circuit breaker to open state
func (cb *CircuitBreaker) ForceOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.setState(CircuitBreakerOpen)
}

// CircuitBreakerStats holds circuit breaker statistics
type CircuitBreakerStats struct {
	State         CircuitBreakerState `json:"state"`
	Failures      int                 `json:"failures"`
	Requests      int                 `json:"requests"`
	SuccessCount  int                 `json:"success_count"`
	FailureRatio  float64             `json:"failure_ratio"`
	LastFailTime  time.Time           `json:"last_fail_time"`
	LastStateTime time.Time           `json:"last_state_time"`
	StateUptime   time.Duration       `json:"state_uptime"`
}

// String returns a string representation of the circuit breaker state
func (state CircuitBreakerState) String() string {
	switch state {
	case CircuitBreakerClosed:
		return "closed"
	case CircuitBreakerOpen:
		return "open"
	case CircuitBreakerHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}
