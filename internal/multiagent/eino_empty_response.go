package multiagent

import (
	"strings"
	"time"

	"veritysec/internal/config"
)

const defaultEmptyResponseContinueMaxAttempts = 5

// IsEinoEmptyResponseResult reports whether Run ended with the "no assistant body captured" placeholder (not a real user-visible reply).
func IsEinoEmptyResponseResult(result *RunResult) bool {
	if result == nil {
		return false
	}
	return isEinoEmptyResponseText(result.Response)
}

func isEinoEmptyResponseText(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	return strings.Contains(s, "no assistant text was captured") ||
		strings.Contains(s, "no assistant text output was captured")
}

// HasEinoResumeTrace reports whether the trace is non-empty, so resume has context to recover.
func HasEinoResumeTrace(result *RunResult) bool {
	if result == nil {
		return false
	}
	s := strings.TrimSpace(result.LastAgentTraceInput)
	return s != "" && s != "[]" && s != "null"
}

// EmptyResponseContinueMaxAttemptsFromConfig is the handler-layer backoff resume cap when there is no assistant body; 0 = default 5.
func EmptyResponseContinueMaxAttemptsFromConfig(mw *config.MultiAgentEinoMiddlewareConfig) int {
	if mw != nil && mw.EmptyResponseContinueMaxAttempts > 0 {
		return mw.EmptyResponseContinueMaxAttempts
	}
	return defaultEmptyResponseContinueMaxAttempts
}

// EmptyResponseContinueBackoff uses the same exponential backoff as run_retry (2s, 4s, 8s… capped).
func EmptyResponseContinueBackoff(attempt int, mw *config.MultiAgentEinoMiddlewareConfig) time.Duration {
	maxBackoff := defaultEinoRunRetryMaxBackoff
	if mw != nil && mw.RunRetryMaxBackoffSec > 0 {
		maxBackoff = time.Duration(mw.RunRetryMaxBackoffSec) * time.Second
	}
	return einoTransientRetryBackoff(attempt, maxBackoff)
}

// FormatEmptyResponseContinueUserMessage is the user turn injected during system auto-resume (not written to the messages table as a bubble).
func FormatEmptyResponseContinueUserMessage() string {
	return strings.TrimSpace(`[System auto-resume / Auto resume]
The previous Eino session produced no visible assistant text (it may have been interrupted mid-stream, or only completed tool calls). Continue from the existing trace and tool results, and provide an interim summary; do not repeat completed steps.`)
}
