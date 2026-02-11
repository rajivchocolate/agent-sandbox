package sandbox

import (
	"errors"
	"fmt"
)

// Sentinel errors for typed error checking.
var (
	ErrTimeout          = errors.New("execution timed out")
	ErrOOM              = errors.New("out of memory")
	ErrPidLimit         = errors.New("pid limit exceeded")
	ErrSecurityViolation = errors.New("security violation detected")
	ErrContainerdDown   = errors.New("containerd unavailable")
	ErrPoolExhausted    = errors.New("container pool exhausted")
	ErrInvalidRequest   = errors.New("invalid execution request")
	ErrUnsupportedLang  = errors.New("unsupported language")
)

// ExecutionError wraps errors with execution context.
type ExecutionError struct {
	ExecID string
	Op     string // The operation that failed
	Err    error
}

func (e *ExecutionError) Error() string {
	if e.ExecID != "" {
		return fmt.Sprintf("execution %s: %s: %s", e.ExecID, e.Op, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Op, e.Err)
}

func (e *ExecutionError) Unwrap() error {
	return e.Err
}

// IsTimeout returns true if the error is a timeout.
func IsTimeout(err error) bool {
	return errors.Is(err, ErrTimeout)
}

// IsOOM returns true if the error is an out-of-memory kill.
func IsOOM(err error) bool {
	return errors.Is(err, ErrOOM)
}

// IsSecurityViolation returns true if the error is a security violation.
func IsSecurityViolation(err error) bool {
	return errors.Is(err, ErrSecurityViolation)
}
