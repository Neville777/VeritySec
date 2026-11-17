package multiagent

import "fmt"

// ExecuteExitError indicates the execute command exited with a non-zero code (an expected failure, not a timeout/interruption/stream error).
type ExecuteExitError struct {
	Code int
}

func (e *ExecuteExitError) Error() string {
	if e == nil {
		return "exit status unknown"
	}
	return fmt.Sprintf("exit status %d", e.Code)
}
